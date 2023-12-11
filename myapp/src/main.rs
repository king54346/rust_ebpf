use std::{mem, ptr};
use std::net::Ipv4Addr;
use anyhow::{Context, Ok};
use aya::maps::{HashMap, AsyncPerfEventArray, RingBuf, PerfEventArray};
use aya::programs::{Xdp, XdpFlags, KProbe, tc, SchedClassifier, TcAttachType, CgroupSkb, CgroupSkbAttachType, BtfTracePoint, FEntry, TracePoint};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf, Btf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn, debug};
use myapp_common::{PacketBuffer, PacketBuffer2, PacketLog, Payload};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{Ipv4Hdr, IpProto};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use tokio::{signal, task}; //提供ctrl-c处理程序

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String, 
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse(); //解析Opt默认是eth0
    //命令行中可以使用RUST_LOG=info 可以指定
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    //去除对锁定内存的限制，兼容旧版Linux内核，旧版内核并不使用较新的基于内存控制组（memcg）的记账系统，memcg管理和限制一组进程的内存使用
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    // include_bytes_aligned 在编译时拷贝bpfelf 目标文件内容
    // Bpf::load 从前一个命令输出中读取bpfelf目标文件的内容，创建映射map ，确保BPF Type Format正确
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/myapp"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp"
    ))?;
    
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    
    // setup_xdp(&mut bpf, &opt)?;
    // setup_kprobe(&mut bpf, &opt)?;
    // setup_perf_event_array(&mut bpf, &opt)?;
    // setup_cgroup_skb(&mut bpf, &opt)?;
    // setup_cgroup_mkdir(&mut bpf, &opt)?;
    // setup_kernel_clone(&mut bpf, &opt)?;
    // setup_sche_process_fork(&mut bpf, &opt)?;
      setup_tc_ringbuf(&mut bpf, &opt)?;
    //setup_tc_perfbuf2(&mut bpf, &opt)?;
    // setup_tc_egress(&mut bpf, &opt)?;
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}


fn setup_perf_event_array(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error> {
    // perfbuffer
    //在 Linux 网络堆栈中为指定的网络接口（由 opt.iface 指定）添加一个 clsact 队列规程（qdisc）
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tc_perfbuf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    // take_map 会将映射的所有权从 Bpf 对象中完全移出，而 map_mut 只提供对映射的临时可变访问，而不改变其在 Bpf 对象中的状态
    let mut events  = AsyncPerfEventArray::try_from(bpf.take_map("DATA").unwrap())?;
    
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    // 处理每个 CPU 上的事件
    for cpu in cpus {
        //打开一个性能事件缓冲区
        let mut buf = events.open(cpu, None)?;
        //通过 tokio::task::spawn 在一个异步块中处理这些事件
        tokio::task::spawn(async move {
            //创建一个缓冲区数组用于接收和存储来自 eBPF 程序的数据
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();

            loop {
                // 异步等待并读取性能事件。对于每个读取的事件，代码解析出网络数据包的内容
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    // 获取 buf 的指针并将其转换为指向 PacketBuffer 类型的指针,read_unaligned从指定的指针位置读取数据
                    let hdr = unsafe { ptr::read_unaligned(buf.as_ptr() as *const PacketBuffer) };
                    // 去掉packbuffer的结构体，处理 PacketBuffer 后面的数据
                    let pkt_buf = buf.split().freeze().slice(
                        mem::size_of::<PacketBuffer>()..mem::size_of::<PacketBuffer>() + hdr.size,
                    );
                    info!("{} bytes", hdr.size);
                    //获取以太网头部的长度
                    let ethhdr = pkt_buf.slice(..EthHdr::LEN);
                    //读取以太网头部结构
                    let ethhdr = unsafe { ptr::read_unaligned(ethhdr.as_ptr() as *const EthHdr) };
                    //跳过非ipv4
                    match ethhdr.ether_type {
                        EtherType::Ipv4 => {}
                        _ => continue,
                    }
                    // 解析 IPv4 头部
                    let ipv4hdr = pkt_buf.slice(EthHdr::LEN..EthHdr::LEN + Ipv4Hdr::LEN);
                    let ipv4hdr =
                        unsafe { ptr::read_unaligned(ipv4hdr.as_ptr() as *const Ipv4Hdr) };
                    // 提取源 IP 地址
                    let src_addr = u32::from_be(ipv4hdr.src_addr);
                    let src_addr = Ipv4Addr::from(src_addr);
                    let src_port = match ipv4hdr.proto {
                        IpProto::Tcp => {
                            let tcphdr = pkt_buf.slice(
                                EthHdr::LEN + Ipv4Hdr::LEN
                                    ..EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN,
                            );
                            let tcphdr =
                                unsafe { ptr::read_unaligned(tcphdr.as_ptr() as *const TcpHdr) };
                            u16::from_be(tcphdr.source)
                        }
                        IpProto::Udp => {
                            let udphdr = pkt_buf.slice(
                                EthHdr::LEN + Ipv4Hdr::LEN
                                    ..EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN,
                            );
                            let udphdr =
                                unsafe { ptr::read_unaligned(udphdr.as_ptr() as *const UdpHdr) };
                            u16::from_be(udphdr.source)
                        }
                        _ => continue,
                    };

                    info!("source address: {:?}, source port: {}", src_addr, src_port);
                }
            }
        });
    }
    Ok(())
}


fn setup_kprobe(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    // kprobe
    let program: &mut KProbe = bpf.program_mut("kprobetcp").unwrap().try_into()?;
    
    program.load()?;
    //附加到函数 tcp_connect
    program.attach("tcp_connect", 0)?;
    Ok(())

}

fn setup_xdp(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{

    //提取xdp程序
    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;//加载进内核
    //附加到网卡接口 如果出错可以XdpFlags::default()改成xdpFlags::SKB_MODE
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;


    // 获取map的引用
    let mut blocklist:HashMap<_,u32,u32>=HashMap::try_from(bpf.take_map("BLOCKLIST").unwrap())?;

    //创建ipv4addr
    let block_addr:u32 = Ipv4Addr::new(180,101,50,242).try_into()?;

    blocklist.insert(block_addr, 0, 0)?;
    Ok(())
}

fn setup_cgroup_skb(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{

    let program: &mut CgroupSkb = bpf.program_mut("cgroup_skb_egress").unwrap().try_into()?;
    //访问和管理使用 cgroups v2 的系统的资源
    let cgroup = std::fs::File::open("/sys/fs/cgroup/unified")?;
     // (1)
     program.load()?;
     // (2)
     program.attach(cgroup, CgroupSkbAttachType::Egress)?;
 
     let mut blocklist: HashMap<_, u32, u32> =
         HashMap::try_from(bpf.take_map("BLOCKLIST").unwrap())?;
 
    let block_addr:u32 = Ipv4Addr::new(180,101,50,242).try_into()?;
 
     // (3)
     blocklist.insert(block_addr, 0, 0)?;
    let mut perf_array =
    AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = Ipv4Addr::from(data.ipv4_address);
                    info!("LOG: DST {}, ACTION {}", src_addr, data.action);
                }
            }
        });
    }
    Ok(())
}


fn setup_cgroup_mkdir(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    let btf = Btf::from_sys_fs()?;
    let program: &mut BtfTracePoint = bpf.program_mut("cgroup_mkdir").unwrap().try_into()?;
    program.load("cgroup_mkdir", &btf)?;
    program.attach()?;
    Ok(())
}


//监听clone 系统调用。clone 是用来创建新的进程
fn setup_kernel_clone(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    let btf = Btf::from_sys_fs()?;
    let program: &mut FEntry = bpf.program_mut("kernel_clone").unwrap().try_into()?;
    program.load("kernel_clone", &btf)?;
    program.attach()?;
    Ok(())
}

fn setup_sche_process_fork(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    let program: &mut TracePoint = bpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;
    Ok(())
}

fn setup_tc_ringbuf(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tc_ringbuf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let mut ring = RingBuf::try_from(bpf.take_map("DATA2").unwrap())?;

    loop {
        if let Some(item) = ring.next() {
            let data = unsafe { &*(item.as_ptr() as *const PacketBuffer2) };
            println!("len{}",data.size);
            let payload = String::from_utf8_lossy(&data.buf[..data.size]);
            println!("payload{:?}",payload);
        }
    }
    Ok(())
}


fn setup_tc_perfbuf2(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier = bpf.program_mut("tc_perfbuf2").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Ingress)?;

    let tcp_payload_map = bpf.take_map("PAYLOAD").expect("can not find map: PAYLOAD");
    let mut payloads = PerfEventArray::try_from(tcp_payload_map)?;

    // eBPF programs are going to write to the EVENTS perf array, using the id of the CPU they're
    // running on as the array index.
    let mut perf_buffers = Vec::new();
    for cpu_id in online_cpus()? {
        // this perf buffer will receive events generated on the CPU with id cpu_id
        perf_buffers.push(payloads.open(cpu_id, None)?);
    }

    let mut out_bufs = [BytesMut::with_capacity(1024)];
    loop {
        for buffer in perf_buffers.iter_mut() {
            if buffer.readable() {
                let r = buffer.read_events(&mut out_bufs)?;
                for buf in out_bufs.iter_mut().take(r.read) {
                    let ptr = buf.as_ptr() as *const Payload;
                    let data = unsafe { ptr.read_unaligned() };
                    info!("len: {}", data.len);
                    let payload = String::from_utf8_lossy(&data.buff[..data.len]);
                    info!("payload: {}", payload);
                }
            }
        
        }
    }
    Ok(())
}


fn setup_tc_egress(bpf: &mut Bpf,opt:&Opt) -> Result<(), anyhow::Error>{
    let _ = tc::qdisc_add_clsact(&opt.iface);
    let program: &mut SchedClassifier =
        bpf.program_mut("tc_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;


    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.take_map("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;


    blocklist.insert(block_addr, 0, 0)?;
    Ok(())
}

