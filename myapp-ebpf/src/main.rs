#![no_std] //ebpf程序不能使用标准库
#![no_main] //没有main函数

use core::{mem, ffi::c_char, slice};

mod binding;
use aya_bpf::{bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT}, macros::{xdp, map, classifier, kprobe, cgroup_skb, btf_tracepoint, fentry, tracepoint, raw_tracepoint}, programs::{XdpContext, TcContext, ProbeContext, SkBuffContext, BtfTracePointContext, FEntryContext, TracePointContext, RawTracePointContext}, maps::{HashMap, PerfEventArray, PerCpuArray, RingBuf}, helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str, bpf_probe_read_user_str_bytes}, BpfContext, PtRegs};
use aya_log_ebpf::info;
use binding::__be32;
use memoffset::offset_of;
use myapp_common::{PacketBuffer, PacketLog, PacketBuffer2, Payload, MAX_MTU, SyscallLog, Filename};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp] 
pub fn myapp(ctx: XdpContext) -> u32 {
    match try_myapp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}



fn try_myapp(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

//必须的，保持编译器正常工作，
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


#[xdp] 
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    // 判断是否为ipv4
    match unsafe { *ethhdr }.ether_type {
        EtherType::Ipv4 => {} //往下执行
        _ => return Ok(xdp_action::XDP_PASS),//通过
    }
    // 获取ipv4的header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    // 解引用一个指向 IPv4 头部的原始指针，获取其中的源 IP 地址字段，然后将该地址从网络字节序（大端）转换为主机字节序
    let source_addr = u32::from_be(unsafe { *ipv4hdr }.src_addr);
    
    let action= if block_ip(source_addr){
        xdp_action::XDP_DROP
    }else{
        let source_port = match unsafe { *ipv4hdr }.proto { //获取协议类型
            IpProto::Tcp => { //基于协议类型处理
                let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;   //计算 TCP/UDP 头部的指针
                u16::from_be(unsafe { *tcphdr }.source)                                         //提取源端口号 （大端）转换
            }
            IpProto::Udp => {
                let udphdr: *const UdpHdr =  ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                u16::from_be(unsafe { *udphdr }.source)
            }
            _ => return Err(()),
        };
        //   :i Ip :X UpperHex  :p,:x LowerHex :MAC UpperMac :mac LowerMac
        info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
        xdp_action::XDP_PASS
    };
   
    Ok(action)
}


// 获取一个T类型并且检查是否越界
#[inline(always)]
 fn ptr_at<T>(ctx:&XdpContext,offset: usize)->Result<*const T,()> {
     let start = ctx.data();
     let end = ctx.data_end();
     let len= mem::size_of::<T>(); //是泛型类型 T 的大小
     if start+offset+len>end {
         return Err(());
     }
     // 返回不可变的T类型指针类型
     Ok((start+offset) as *const T)     
 }


 #[map]
 static BLOCKLIST:HashMap::<u32,u32> = HashMap::<u32,u32>::with_max_entries(1024, 0);

//  检查应该允许还是拒绝数据包,在map中的被block
 fn block_ip(address:u32)->bool{
    unsafe{BLOCKLIST.get(&address).is_some()}
 }




// perfbuffer
 #[map]
pub static DATA: PerfEventArray<PacketBuffer> = PerfEventArray::new(0);

#[classifier]
pub fn tc_perfbuf(ctx: TcContext) -> i32 {
    match try_tc_perfbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
// 处理网络流量时捕获数据包信息,并通过性能事件数组将信息传递到用户空间
fn try_tc_perfbuf(ctx: TcContext) -> Result<i32, i32> {
    DATA.output(
        &ctx,
        &PacketBuffer {
            size: ctx.len() as usize,
        },
        ctx.len(),
    );
    Ok(0)
}

// kprobe
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

use crate::binding::{sock, sock_common, iphdr};
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
//获和记录 TCP 网络连接的源和目的地址信息
//binding从系统中预安装的 Linux 内核头文件生成 Rust 绑定.
//从 生成 Rust 绑定vmlinux.h。vmlinux 是 Linux 内核的映像，包含了内核的全部符号和数据类型。
// 返回值0表成功，非零值表示各种错误或状态代码。
#[kprobe]
pub fn kprobetcp(ctx: ProbeContext) -> u32 {
    match try_kprobetcp(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_kprobetcp(ctx: ProbeContext) -> Result<u32, i64> {
    //函数首先尝试获取当前网络套接字的指针（sock）
    let sock: *mut sock = ctx.arg(0).ok_or(1i64)?;
    //它读取套接字的公共部分（sock_common）来获取网络地址信息
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
            .map_err(|e| e)?
    };
    //skc_family表示套接字的地址族 其他地址族，如 AF_UNIX（本地通信）、AF_PACKET（底层网络协议访问）等。
    match sk_common.skc_family {
        //IPv4 地址
        AF_INET => {
            let src_addr = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
            });
            let dest_addr: u32 = u32::from_be(unsafe {
                sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
            });
            //记录日志
            info!(
                &ctx,
                "AF_INET src address: {:i}, dest address: {:i}",
                src_addr,
                dest_addr,
            );
            Ok(0)
        }
        //IPv6 地址
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET6 src addr: {:i}, dest addr: {:i}",
                unsafe { src_addr.in6_u.u6_addr8 },
                unsafe { dest_addr.in6_u.u6_addr8 }
            );
            Ok(0)
        }
        _ => Ok(0),
    }
}


#[fentry]
//监控内核中进程的创建
//内核函数 pid_t kernel_clone(struct kernel_clone_args *args)
pub fn kernel_clone(ctx: FEntryContext) -> u32 {
    match  try_kernel_clone(ctx){
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kernel_clone(ctx: FEntryContext) -> Result<u32, u32> {
    // 获取进程信息
    let pid = ctx.pid();
    // 获取进程的命令行字符串。如果获取失败，返回错误
    let command = ctx.command().map_err(|e| e as u32)?;
    // 转换命令行字符串
    
    let command = unsafe{
        core::str::from_utf8_unchecked(&command[..])
    };

    info!(&ctx, "new process: pid: {}, command: {}", pid, command);

    Ok(0)
}

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_pub_progs(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_pub_progs(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sched_process_fork called");
    Ok(0)
}

// #[map]
// static EVENTS: PerfEventArray<PacketLog> =
//     PerfEventArray::with_max_entries(1024, 0);

const ETH_P_IP: u32 = 8;

// // 附加在v2 cgroup
// #[cgroup_skb]
// pub fn cgroup_skb_egress(ctx: SkBuffContext) -> i32 {
//     match { try_cgroup_skb_egress(ctx) } {
//         Ok(ret) => ret,
//         Err(_) => 0,
//     }
    
// }

// fn try_cgroup_skb_egress(ctx: SkBuffContext) -> Result<i32, i64> {
//     //  获取数据包的协议类型
//     let protocol = unsafe { (*ctx.skb.skb).protocol };
//     //检查数据包是否为 IPv4 协议的数据包
//     if protocol != ETH_P_IP {
//         return Ok(1);
//     }
//     let anon_1_offset = offset_of!(iphdr, __bindgen_anon_1);
//     let daddr_offset = anon_1_offset + mem::size_of::<__be32>();
//     //提取目的 IP 地址
//     let destination = u32::from_be(ctx.load(daddr_offset)?);

//     // 决定数据包是否被阻止
//     let action = if block_ip(destination) { 0 } else { 1 };
    
//     let log_entry = PacketLog {  
//         ipv4_address: 111,
//         action: 1,
//     };
//     EVENTS.output(&ctx, &log_entry, 0);
//     Ok(1)
// }


const LOG_BUF_CAPACITY: usize = 64;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

//基于每个 CPU 的数组
#[map]
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[btf_tracepoint]
//监控 cgroup 的创建事件,
pub fn cgroup_mkdir(ctx: BtfTracePointContext) -> i32 {
    match { try_cgroup_mkdir(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_cgroup_mkdir(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let path:&str = unsafe {
        let path: *const c_char = ctx.arg(1);
        let buf = BUF.get_ptr_mut(0).ok_or(0)?;
        //结果是一个指向目标缓冲区中实际读取的字节切片的引用
        let bytes = match bpf_probe_read_kernel_str_bytes(path as *const u8, &mut (*buf).buf) {
            Ok(slice) => slice,
            Err(_) => return Err(-1),
        };
        //不检查字节切片是否包含有效的 UTF-8 数据
         core::str::from_utf8_unchecked(bytes)
    };
 

    info!(&ctx, "tracepoint cgroup_mkdir called: {}", path);
    
    if path.starts_with("/sys/fs/cgroup") {
        info!(&ctx, "cgroup");
    }
    if path.starts_with("/system.slice/docker") {
        info!(&ctx, "docker cgroup");
    }

    Ok(0)
}



#[map]
static mut PAYLOAD: PerfEventArray<Payload> = PerfEventArray::with_max_entries(1024, 0);
#[map]
static REGISTERS: PerCpuArray<Payload> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
pub fn tc_perfbuf2(ctx: TcContext) -> i32 {
    match try_tc_perfbuf2(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_tc_perfbuf2(ctx: TcContext) -> Result<i32, i32> {
    // version1
    // let mut payload = Payload {
    //     buff: [0u8; 256],
    //     len: 0,
    // };
    // let len = ctx.skb.len() as usize;

    //   // 确保不超过 Payload 的 data 数组大小
    // let len_to_copy = if len > 512 {
    //     256
    // } else {
    //     len
    // };
    // // invaild zero 检查
    // if len_to_copy == 0 {
    //     return Err(TC_ACT_PIPE);
    // }
    // // 安全检查过bpf的验证器
    // if len < 256 {
    //     return Err(TC_ACT_PIPE);
    // }
    // // 将数据从 skb 复制到 Payload 的 data 字段
    // ctx.load_bytes(0, &mut payload.buff[..256]).map_err(|_| TC_ACT_PIPE)?;

    // payload.len = len_to_copy;
    // unsafe {
    //     PAYLOAD.output(&ctx, &payload, 0)
    // }

    // version2
    let p = REGISTERS.get_ptr_mut(0).ok_or(0)?;

    let size = ctx.skb.len() as usize;

    let len_to_copy = if size > MAX_MTU {
        MAX_MTU
    } else {
        size
    };
    // 检查 size 是否过小
    // if size < len_to_copy {
    //     return Err(TC_ACT_PIPE);
    // }

    // 安全检查过bpf的验证器
    if size < MAX_MTU {
        return Err(TC_ACT_PIPE);
    }


    unsafe {
         // invaild zero 检查
         //    if len_to_copy == 0 {
         //        return Err(TC_ACT_PIPE);
         //    }


            ctx.load_bytes(0, &mut (*p).buff).map_err(|_| TC_ACT_PIPE)?;
            (*p).len = len_to_copy;
     }
  
    
    
    unsafe {
        PAYLOAD.output(&ctx, &mut *p, 0)
    }
    Ok(TC_ACT_PIPE)
}



#[map]
static DATA2: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[classifier]
pub fn tc_ringbuf(ctx: TcContext) -> i32 {
    match try_tc_ringbuf(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
fn try_tc_ringbuf(ctx: TcContext) -> Result<i32, i32> {
    // info!(&ctx, "received a packet");

    // TODO(vaodorvsky): This should be faster, but sadly it's annoying the
    // verifier.
    // if let Some(mut buf) = DATA.reserve::<PacketBuffer>(0) {
    //     let len = ctx.skb.len() as usize;
    //     let buf_inner = unsafe { &mut (*buf.as_mut_ptr()).buf };

    //     unsafe { (*buf.as_mut_ptr()).size = len };
    //     ctx.load_bytes(0, buf_inner).map_err(|_| TC_ACT_PIPE)?;

    //     buf.submit(0);
    // }

    // This is slower (`output` method is going to perform a copy)... and it
    // also annoys the verifier, FML.
    // let buf = unsafe {
    //     let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
    //     &mut *ptr
    // };
    // if buf.buf.len() < MAX_MTU {
    //     return Err(TC_ACT_PIPE);
    // }
    // if ctx.data() + MAX_MTU > ctx.data_end() {
    //     return Err(TC_ACT_PIPE);
    // }

    // ctx.load_bytes(0, &mut buf.buf[..MAX_MTU])
    //     .map_err(|_| TC_ACT_PIPE)?;

    // DATA.output(buf, 0).map_err(|_| TC_ACT_PIPE)?;

    // Just send the struct for now, without filling it up with packet data.

           
    // 为每个捕获的网络包分配一个 PacketBuffer 结构体，并设置其 size 字段为网络包的长度
 if let Some(mut buf) = DATA2.reserve::<PacketBuffer2>(0) {
        let len = ctx.skb.len() as usize;

         let len_to_copy = if len > MAX_MTU {
             MAX_MTU
         } else {
             len
         };
         // let buf_inner = unsafe { &mut () };
         if len < MAX_MTU {
             buf.discard(0);
             return Err(TC_ACT_PIPE);
         }

        // if len == 0 || len > 128 {
        //     buf.discard(0);
        //     return Err(TC_ACT_PIPE);
        // }
        unsafe {
            if ctx.load_bytes(0, &mut (*(buf.as_mut_ptr())).buf).is_ok() {
                (*buf.as_mut_ptr()).size = len_to_copy;
                buf.submit(0);
            } else {
                buf.discard(0);
                return Err(TC_ACT_PIPE);
            }
        }

    }

    Ok(TC_ACT_PIPE)
}



#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = u32::from_be(ipv4hdr.dst_addr);

    // action 3 表示继续传输，2表示丢弃
    let action = if block_ip(destination) {
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };

    info!(&ctx, "DEST {:i}, ACTION {}", destination, action);

    Ok(action)
}




#[map]
static mut PIDS: HashMap<u32, Filename> = HashMap::with_max_entries(10240000, 0);

#[kprobe]
pub fn log_pid(ctx: ProbeContext) -> u32 {
    match unsafe { try_log_pid(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_log_pid(ctx: ProbeContext) -> Result<u32, u32> {
    //  
    let pid = ctx.pid();
    let mut f = Filename {
        filename: [0u8; 127],
        filename_len: 0,
    };
    // 
    if PIDS.get(&pid).is_none() {
        let regs = PtRegs::new(ctx.arg(0).unwrap());

        let filename_addr: *const u8 = regs.arg(0).unwrap();
               
       bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut f.filename[0..127]).map_err(|e| e as u32)?;
            // let filename_len = ;
        f.filename_len=127;
       
        if PIDS.insert(&pid, &f, 0).is_err() {
           return  Err(1);
        };
    }
    Ok(0)
}


#[map]
static mut EVENTS1: PerfEventArray<SyscallLog> =PerfEventArray::<SyscallLog>::with_max_entries(1024, 0);

#[raw_tracepoint]
pub fn log_syscall(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_log_syscall(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}
// 每次调用触发时捕获进程ID和系统调用编号
unsafe fn try_log_syscall(ctx: RawTracePointContext) -> Result<u32, u32> {
    let args = slice::from_raw_parts(ctx.as_ptr() as *const usize, 2);
    let syscall = args[1] as u64;
    let pid = ctx.pid();
    
    let log_entry = SyscallLog {
        pid,
        syscall: syscall as u32,
    };
    
    EVENTS1.output(&ctx, &log_entry, 0);
    Ok(0)
}
