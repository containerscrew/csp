#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEventIpv4 {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub protocol: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEventIpv6 {
    pub src_addr: u128,
    pub dst_addr: u128,
    pub protocol: u8,
}
