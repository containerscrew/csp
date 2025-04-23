#![no_std]
#![no_main]


use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};

use aya_log_ebpf::info;
use network_types::{eth::EthHdr, ip::{IpProto, Ipv4Hdr}};


const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

#[cgroup_skb]
pub fn csp(ctx: SkBuffContext) -> i32 {
    match try_csp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret, 
    }
}

fn try_csp(ctx: SkBuffContext) -> Result<i32, i32> {
    let protocol = unsafe { (*ctx.skb.skb).protocol } as u16;
    let eth_proto = u16::from_be(protocol);

    match eth_proto {
        ETH_P_IP => {
            // Handle IPv4 packets
            // let dst_addr = ctx.load::<u32>(offset_of!(Ipv4Hdr, dst_addr))
            //     .map_err(|_| 0)?;
            let ip_hdr = ctx.load::<Ipv4Hdr>(EthHdr::LEN).map_err(|_| 0)?;

            let proto = ip_hdr.proto;
            match proto {
                IpProto::Tcp => {
                    info!(&ctx, "TCP packet detected");
                }
                IpProto::Udp => {
                    info!(&ctx, "UDP packet detected");
                }
                IpProto::Icmp => {
                    info!(&ctx, "ICMP packet detected");
                }
                _ => return Ok(1),
            }

            let dst_addr = ip_hdr.dst_addr();
            let src_addr = ip_hdr.src_addr();
            
            info!(&ctx, "IPv4 packet detected. Src: {} Dst: {}", src_addr, dst_addr);
            
        },
        ETH_P_IPV6 => {
            // Handle IPv6 packets
            info!(&ctx, "IPv6 packet detected");
        },
        _ => {
            info!(&ctx, "Unknown protocol {}", protocol);
            return Ok(1);
        }
    }

    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
