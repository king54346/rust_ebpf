#![no_std] //ebpf程序不能使用标准库
#![no_main] //没有main函数

use core::mem;

use aya_bpf::{bindings::xdp_action, macros::{xdp, map}, programs::XdpContext, maps::HashMap};
use aya_log_ebpf::info;
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

//  检查应该允许还是拒绝数据包
 fn block_ip(address:u32)->bool{
    unsafe{BLOCKLIST.get(&address).is_some()}
 }