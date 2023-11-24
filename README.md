# myapp

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```


抓包工具 ： libpcap，dpdk(DPDK专注于用户空间的高性能数据包处理，适用于高吞吐量网络应用。)，ebpf(应用场景：用于网络监控、安全增强、性能分析等多种场景。)，xdp(应用场景：广泛用于构建高性能的网络功能，如DDoS防御、负载均衡。)，PF_RING(应用场景：主要用于网络监控、安全分析和流量捕获)

myapp-ebpf 运行于内核
myapp 运行于用户程序
cargo xtask == cargo run --package xtask --

cargo xtask build-ebpf
验证ebpf程序
llvm-objdump -s target/epfel-unknow-none/debug/myapp
<LBB0_2>中 r0=2 将寄存器0设为2(XDP_PASS动作的值) exit退出程序
用用户空间加载ebpf二进制文件，并attach到追踪点，逻辑在myapp/src/main.rs中
程序一直执行下去，直到按下ctrl-c 退出时候，aya负责卸载程序
当myapp运行的时候如果发出sudo bpftool prog list 命令可以验证是否被加载
可以将数据解析到L7,但是限制为L3层
xdpContext 包含两个字段data和data_end,指的是数据包的头尾指针，引入ptr_at辅助函数检查指针是否在范围内




使用network types crates 定义常见的协议类型定义( IP 地址、网络接口、端口号等的结构)

在ebpf程序中创建一个map
#[map]
static BLOCKLIST:HashMap<> = HashMap::with_max_entries(1024,0)
HashMap 由aya提供。
用户空间获取map
获取BLOCKLIST MAP 的引用，insert插入


Packet 套接字 可以使用 Packet 套接字来接收或发送在网络层（如 IP 层）的原始数据包，支持用户空间在实现物理层上协议模块
type：
    SOCK_RAW： 允许程序接收和发送包括头部在内的原始数据包。这对于实现新的协议或直接与网络层交互非常有用。
    SOCK_DGRAM： 用于特定协议的数据报服务（例如 ICMP）。
protocol：
    IP
    icmp
    arp
    ethernet

pnet 是 Rust 语言的一个 crate（包），用于网络编程。它提供了对底层网络协议的直接访问，允许开发者在 Rust 中实现低级网络操作，主要集中在监控和分析网络流量
Netfilter(iptables 和 eBPF 执行其功能的基础架构) 和 iptables(基于 Netfilter 构建的一个用户空间工具) epbf 等可用于拦截网络流量

混杂模式（Promiscuous Mode）是网络接口卡（NIC）的一种工作模式，使得网络接口能够接收经过它的所有数据包，而不仅仅是那些明确发送给它的数据包

packet_fanout 是 Linux 内核中的一个特性 用于实现在多个应用程序间高效分发网络数据包,它允许将从同一个物理或虚拟网络接口收到的数据包分发给多个用户空间进程，从而实现对网络数据包的并行处理。

pselect和select 基本一致，除了超时时间是ns级，后一个参数可以指定一个信号屏蔽字填NULL同select，否则sigmask指向一有效的信号屏蔽字(阻塞信号，例如ctrl+c)，在调用pselect时，以原子操作的方式安装该信号屏蔽字，在返回时，恢复以前的信号屏蔽字

第 2 层：数据链路层
主要协议：以太网（Ethernet）
头部结构：以太网头部通常包含以下字段：
目标 MAC 地址（6 字节）
源 MAC 地址（6 字节）
类型/长度字段（2 字节）

第 3 层：网络层
主要协议：IP（Internet Protocol），分为 IPv4 和 IPv6
IPv4 头部结构：
版本（4 位）
头部长度（4 位）
服务类型（8 位）
总长度（16 位）
标识（16 位）
标志和片偏移（16 位）
生存时间（TTL，8 位）
协议（8 位）
头部校验和（16 位）
源 IP 地址（32 位）
目标 IP 地址（32 位）
IPv6 头部结构：更为简化，包括版本、流标签、载荷长度、下一个头部、跳限制、源和目标地址。

IPv4 的头部包含许多可选字段，这使得头部的解析变得复杂。
IPv6 头部固定长度为 40 字节，不包含任何可选字段，简化了头部解析。
IPv4 需要在网络层处理分片和重组，这增加了复杂性和处理开销。(在IPv4中，路由器在必要时会进行分片 ，如“标识”、“标志”和“片偏移”存储分片的信息,在IPv4中，只有最终目的地（接收端）IP主机端负责进行重组,IPv6中取消了路由器的分片能力,避免分片)

IPv6 设计中去除了网络层的分片和重组功能，将这一责任转移给传输层和应用层，简化了网络层的处理。
IPv4 的地址和路由管理较为复杂，需要使用子网掩码、地址转换（NAT）等技术。
IPv6 通过更好的地址分配机制（如基于前缀的聚合）简化了路由，减少了路由表的大小和复杂性。

第 4 层：传输层
主要协议：TCP（Transmission Control Protocol）和 UDP（User Datagram Protocol）
TCP 头部结构：
源端口（16 位）
目标端口（16 位）
序列号（32 位）
确认号（32 位）
数据偏移（4 位）、保留（3 位）、标志（9 位）
窗口大小（16 位）
校验和（16 位）
紧急指针（16 位）
UDP 头部结构：
源端口（16 位）
目标端口（16 位）
长度（16 位）
校验和（16 位）