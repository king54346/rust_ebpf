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

Perf Buffer: 由于其与 perf events 的紧密结合，更适合于性能监控和事件跟踪的场景，尤其是当涉及到复杂的事件数据或需要与现有的 perf 工具集成时。
#[map]
static EVENTS: PerfEventArray<PacketLog> = PerfEventArray::with_max_entries(1024, 0);

Ring Buffer: 更适用于需要高效、连续数据流传输的场景，如日志记录、跟踪和实时分析。
#[map]
static DATA2: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

Ring buffer 由于其简单高效的设计，在高速数据传输场景中可能是更好的选择，而 perf buffer 在需要与性能事件子系统集成或处理复杂事件时可能更合适。
PerCpuArray 是一种特殊类型的 eBPF 映射（map），它用于存储和管理每个 CPU 核心的私有数据。适用于那些需要在每个 CPU 核心上独立累积或处理数据的应用，比如统计数据或临时缓冲区
#[map]
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);



#[xdp]
XDP 提供了更好的性能，因为它执行得更早 - 它从 NIC 驱动程序接收原始数据包，然后再进入内核网络堆栈的任何层并解析为结构sk_buff。

#[kprobe]
探测 BPF 程序附加到内核 (kprobes) 或用户端 (uprobes) 函数，并且能够访问这些函数的函数参数
关于附加函数，如监控网络连接，可能会选择像 tcp_connect 这样的函数；如果是文件系统操作，则可能会选择 open、read 或 write 等函数
导出所有的系统调用   ausyscall --dump
寄存器状态：ProbeContext 通常允许你访问系统调用或其他被探测函数时的 CPU 寄存器状态。这包括可以用来获取系统调用参数的通用寄存器。


网络通信：
tcp_connect：当一个 TCP 连接被建立时调用。
udp_sendmsg 和 udp_recvmsg：用于跟踪 UDP 消息的发送和接收。
sock_sendmsg 和 sock_recvmsg：监控所有类型套接字的数据发送和接收。

文件系统操作：
vfs_read 和 vfs_write：虚拟文件系统（VFS）层的读写操作。
do_sys_open：当打开文件时调用。
ext4_file_write：跟踪特定于 ext4 文件系统的写操作。

进程和调度：
do_fork：监控进程创建。
do_exit：当进程退出时调用。
schedule：用于跟踪进程调度决策。

系统调用：
sys_clone、sys_execve 和 sys_exit：分别用于跟踪进程克隆、执行新程序和进程退出的系统调用。
sys_write 和 sys_read：标准的写入和读取系统调用。

内存管理：
__alloc_pages_nodemask：内存分配时调用。
free_pages：释放内存页面时调用。

安全相关：
security_socket_create：创建套接字时进行安全检查。
security_file_open：打开文件的安全检查。

驱动和硬件交互：
usb_submit_urb：USB 请求块（URB）提交时调用。
blk_account_io_start：开始磁盘 I/O 操作时调用。

#[cgroup_skb]
cgroup_skb 是一种 eBPF 程序类型，它可以附加到特定的控制组。
当控制组内的进程发送或接收网络数据包时，cgroup_skb 程序会被调用，允许对这些数据包进行处理。
用于监控和记录通过特定控制组的网络活动


#[classifier]
它附加到Linux 内核网络中的排队规则 （通常称为qdisc），因此能够对与 qdisc 关联的网络接口上收到的数据包做出决策。
qdisc（队列规程，Queueing Discipline）是 Linux 网络子系统中的一个关键组件,它是 Linux 流量控制（Traffic Control, TC）架构的核心部分,负责处理数据包的排队、调度和转发.
对于每个网络接口，都有单独的 qdisc 用于入口和出口流量。将分类器程序附加到接口时
分类器可以检查入口和出口流量。XDP 仅限于入口。


cgroup_skb:
    这种类型的 eBPF 程序附加到控制组（cgroup）上，用于处理进入和离开控制组的套接字缓冲区（skb）。它可以用于实现基于控制组的网络策略，如流量控制和包过滤。
cgroup_sock_addr:
    附加到控制组的 eBPF 程序，用于处理套接字层面的地址相关操作，如绑定（bind）和连接（connect）操作。这可以用于控制基于控制组的网络访问和权限。
stream_verdict:
    用于处理 TCP 流量的 eBPF 程序类型，允许在 TCP 流中进行数据包检查和修改。这对于实现基于内容的网络策略非常有用。

socket_filter:
    附加到套接字上的 eBPF 程序，用于在数据包接收或发送前进行过滤。这类似于传统的套接字过滤，可以用于捕获或丢弃特定类型的网络流量。

fentry / fexit:
    这两种 eBPF 程序类型分别附加到内核函数的入口（fentry）和出口（fexit）。它们用于在特定的内核函数被调用之前或之后执行代码，可以用于监控和修改内核函数的行为。
   系统调用相关：
        sys_open / __x64_sys_open：
        对应于内核函数 do_sys_open。
        sys_close / __x64_sys_close：
        对应于内核函数 __close_fd。
        sys_read / __x64_sys_read：
        对应于内核函数 ksys_read。
        sys_write / __x64_sys_write：
        对应于内核函数 ksys_write。
        sys_execve / __x64_sys_execve：
        对应于内核函数 do_execve。
        sys_clone / __x64_sys_clone：
        对应于内核函数 kernel_clone。
        sys_fork / __x64_sys_fork：
        对应于内核函数 kernel_clone，但具有不同的参数。
    网络堆栈函数：
        tcp_sendmsg：
        对应于内核的 TCP 协议栈实现。
        tcp_recvmsg：
        同样对应于内核的 TCP 协议栈实现。
        ip_rcv：
        对应于内核中的 ip_rcv 或 ip_rcv_finish 等函数。
        ip_send_skb：
        对应于内核中的 ip_output 或 ip_finish_output 等函数。
    进程管理：
        do_fork：
        对应于内核函数 kernel_clone。
        do_exit：
        对应于内核函数 do_exit。
        schedule：
        对应于内核函数 schedule。
    文件系统操作：
        vfs_read：
        对应于内核函数 new_sync_read 或 vfs_read。
        vfs_write：
        对应于内核函数 new_sync_write 或 vfs_write。
        ext4_file_open：
        对应于内核的 ext4 文件系统模块中的 ext4_file_open 函数。
    内存管理：
        do_page_fault：
        对应于内核函数 handle_mm_fault。
        alloc_pages_vma：
        对应于内核的内存分配相关函数，如 alloc_pages_current。
    块设备操作：
        blk_start_request：
        对应于内核块层的 blk_start_request。
        blk_mq_start_request：
        对应于内核块层的 blk_mq_start_request。
    https://codebrowser.dev/linux/linux/

sk_lookup:
    这种类型的 eBPF 程序用于影响套接字的选择过程。它允许在网络堆栈中更早地进行套接字选择和路由决策，可以用于实现复杂的负载均衡和网络路由策略。

cgroup_device:
    附加到控制组的 eBPF 程序，用于处理设备访问权限。这可以用于限制或监控控制组内进程对特定设备的访问。
cgroup_sysctl:
    附加到控制组的 eBPF 程序，用于拦截和处理 sysctl 操作。这可以用于在控制组级别覆写或修改内核参数。
sk_msg:
    用于处理套接字消息的 eBPF 程序类型，允许在数据包发送和接收的过程中进行检查和修改。这对于实现更复杂的网络控制策略非常有用。
sock_ops:
    该类型的 eBPF 程序专注于套接字级别的操作，允许在更高层次上控制和管理套接字行为，例如 TCP 套接字的生命周期事件。

uprobe / uretprobe:
    通过符号表可以拿到函数的虚拟内存地址，通过节表拿到.text 节的虚拟内存地址，以及.text 节相较于 ELF 起始地址的偏移量。
    offset= 函数的虚拟地址 -  .text 段的虚拟地址 + .text 端偏移量
    函数的指令在 二进制文件的偏移量就可以计算出来了


kprobe / kretprobe:
    Kprobes 是一个动态 tracing 机制，能够动态的注入到内核的任意函数中的任意地方，采集调试信息和性能信息，并且不影响内核的运行。
    动态追踪指的是在运行时动态地插入追踪点，无需修改或重新编译目标应用程序或操作系统的代码。
    kprobe（内核探测点）和 kretprobe（内核返回探测点）用于在内核函数的入口（kprobe）和出口（kretprobe）处执行代码，用于监控、调试和追踪内核函数的调用。
    fentry/fexit 提供了一种高效、低开销的方式来监控内核函数的入口和出口，但它们的使用受限于内核版本和构建配置。
    kprobe 提供了一种更通用但可能开销更大的方式来监控几乎任何内核函数，它更适用于那些没有 fentry/fexit 支持的内核版本或特殊的监控需求（5.5+）才能支持。
    fentry/fexit直接获取指针提供给bpf程序，kprobe放到ctx这个map里供调用，需要通过查询map来拿到参数

lsm:
    Linux 安全模块（LSM）的 eBPF 程序，用于扩展内核的安全策略。它可以用来创建或增强安全机制，如访问控制和权限检查。
    文件系统操作
    打开、创建、移动和删除文件
    挂载和卸载文件系统
    任务/流程操作
    分配和释放任务，更改任务的用户和组标识
    套接字操作
    创建和绑定套接字
    接收和发送消息
    内核版本至少为 5.7。
    BPF LSM 已启用 cat /sys/kernel/security/lsm

raw_tracepoint:
    附加到内核的原始追踪点的 eBPF 程序，用于在特定的内核执行点捕获事件。这对于高级监控和性能分析非常有用。
    不需要依赖 perf event( Linux 内核的一种性能分析工具)
    不论是 kprobes、tracepoint 类型的 eBPF 程序，都是复用 perf event 来实现 probe handler 注入
    raw_tracepoint不需要依赖 perf event，eBPF 程序直接作为 probe handler 注册到 tracepoint 上。
    相比于 tracepoint ，raw tracepoint 有更好的性能

btf_tracepoint: 
    基于 BTF (BPF Type Format) 的追踪点，允许在内核追踪点处附加 eBPF 程序，同时利用 BTF 提供的类型信息进行更复杂的数据访问和处理。

tracepoint:
    Tracepoint 是一个静态的 tracing 机制，开发者在内核的代码里的固定位置声明了一些 Hook 点，通过这些 hook 点实现相应的追踪代码插入，一个 Hook 点被称为一个 tracepoint。
    静态追踪是指在应用程序或系统代码中预先定义的追踪点。这些追踪点在编译时嵌入到代码中，运行时可用于收集数据。
    tracepoint 类型的 eBPF 程序用于挂钩到内核中预定义的追踪点。
    需要挂载tracfers   sudo mount -t tracefs tracefs /sys/kernel/tracing
    TraceFS 是 Linux 内核提供的一个虚拟文件系统，他提供了一组文件和目录，用户可以通过读写这些文件和目录来与内核中的跟踪工具交互。



tracepoint 提供了一种高级、易于使用的方式来追踪内核行为，适合大多数常规用途。
raw_tracepoint 提供了更低级别的访问，适用于需要更精细控制的高级用途。
btf_tracepoint 利用 BTF 信息，提供了丰富的类型安全的追踪能力，适用于需要深入内核数据结构的高级用途。




XDP:
    XDP 是最早介入数据包处理的，它直接在网络驱动层处理数据包，甚至在数据包被内核网络堆栈接收之前.
    XDP 可以决定是否将数据包传递给内核网络堆栈，或者直接丢弃、重定向等。因为它在非常低的层次操作，所以非常高效

cgroup_skb：
    如果数据包被传递给了内核网络堆栈，cgroup_skb 类型的 eBPF 程序可以在控制组层面上处理数据包。这包括应用特定的策略或规则，比如安全检查或流量控制。

qdisc:
    在数据包进入内核网络堆栈后（如果 XDP 没有丢弃或重定向它们），它们会被送到网络接口的队列规程（qdisc）
    clsact 是一种特殊的 qdisc，允许在数据包进入（ingress）或离开（egress）接口时进行处理。这包括对数据包进行分类、排队或执行其他 TC 动作
    qdisc 主要负责数据包的排队和调度策略，影响着数据包的发送时间和顺序

tcp_connect（和其他网络相关的系统调用）:
    tcp_connect 是应用程序发起 TCP 连接时内核中执行的函数。这通常发生在应用层，远高于 XDP 和 qdisc 的层次
    当应用程序执行如 connect 系统调用建立 TCP 连接时，内核中的 tcp_connect 函数会被触发。这涉及到 TCP 三次握手的初始化等操作。




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




/// An [`Array`] map.
Array(MapData),
基本的数组类型 map，支持基于索引的访问。
/// A [`BloomFilter`] map.
BloomFilter(MapData),
布隆过滤器类型的 map，用于快速检查一个元素是否在一组元素中，有一定的误判率。
/// A [`CpuMap`] map.
CpuMap(MapData),
用于映射 CPU 和某些资源或属性。
/// A [`DevMap`] map.
DevMap(MapData),
用于设备映射，如网络设备。
/// A [`DevMapHash`] map.
DevMapHash(MapData),
哈希表形式的设备映射。
/// A [`HashMap`] map.
HashMap(MapData),
/// A [`LpmTrie`] map.
LpmTrie(MapData), 
最长前缀匹配（Longest Prefix Match）Trie，用于路由和网络相关的查找。
/// A [`HashMap`] map that uses a LRU eviction policy.
LruHashMap(MapData),
最近最少使用（Least Recently Used）策略的哈希表
/// A [`PerCpuArray`] map.
PerCpuArray(MapData),
为每个 CPU 核心提供一个数组，用于存储每个核心的特定数据
/// A [`PerCpuHashMap`] map.
PerCpuHashMap(MapData),
为每个 CPU 核心提供一个哈希表。
/// A [`PerCpuHashMap`] map that uses a LRU eviction policy.
PerCpuLruHashMap(MapData),
为每个 CPU 核心提供一个使用 LRU 策略的哈希表
/// A [`PerfEventArray`] map.
PerfEventArray(MapData),
/// A [`ProgramArray`] map.
ProgramArray(MapData),
存储 eBPF 程序引用的数组，允许一个 eBPF 程序调用另一个。
/// A [`Queue`] map.
Queue(MapData),
基本的先进先出（FIFO）队列。
/// A [`RingBuf`] map.
RingBuf(MapData),
/// A [`SockHash`] map
SockHash(MapData),
用于存储 socket 引用的哈希表。
/// A [`SockMap`] map.
SockMap(MapData),
用于存储 socket 引用的 map。
/// A [`Stack`] map.
Stack(MapData),
基本的后进先出（LIFO）栈。
/// A [`StackTraceMap`] map.
StackTraceMap(MapData),
用于存储栈跟踪信息。
/// An unsupported map type.
Unsupported(MapData),
/// A [`XskMap`] map.
XskMap(MapData),
用于 XDP（eXpress Data Path）套接字。