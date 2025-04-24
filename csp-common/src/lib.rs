#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEvent {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub protocol: u8,
}
