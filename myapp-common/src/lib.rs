#![no_std]
pub const MAX_MTU: usize = 1518;
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PacketBuffer {
    pub size: usize,
   
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct PacketBuffer2 {
    pub size: usize,
    pub buf: [u8; MAX_MTU],
}

#[cfg(feature = "user")]
pub mod user {
    use super::*;

    unsafe impl aya::Pod for PacketBuffer {}
    unsafe impl aya::Pod for PacketBuffer2 {}
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Payload {
    pub buff: [u8; MAX_MTU],
    pub len: usize
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SyscallLog {
    pub syscall: u32,
    pub pid: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SyscallLog {}


#[repr(C)]
#[derive(Copy, Clone)]
pub struct Filename {
    pub filename: [u8; 127],
    pub filename_len: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Filename {}