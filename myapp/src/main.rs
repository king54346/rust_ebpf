


use std::net::Ipv4Addr;

use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal; //提供ctrl-c处理程序

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
    //提取xdp程序
    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;//加载进内核
    //附加到网卡接口 如果出错可以改成xdpFlags::SKB_MODE
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;


    // 获取map的引用
    let mut blocklist:HashMap<_,u32,u32>=HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    //创建ipv4addr
    let block_addr:u32 = Ipv4Addr::new(180,101,50,242).try_into()?;

    blocklist.insert(block_addr, 0, 0)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
