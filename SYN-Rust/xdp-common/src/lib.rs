#![no_std]
use zerocopy::{FromBytes, Unaligned};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Unaligned)]
pub struct PacketLog {
    pub src_addr: [u8; 16],
    pub port: [u8; 2],
    pub version: u16,
}

impl PacketLog {
    pub fn port(&self) -> u16 {
        u16::from_be_bytes(self.port)
    }
}
