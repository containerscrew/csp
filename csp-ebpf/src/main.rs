#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};

use aya_log_ebpf::{info, warn};
use network_types::ip::{IpProto, Ipv4Hdr};

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
            // Load only the 'proto' field from the IPv4 header using its byte offset.
            // Useful when you want a specific field without reading the entire struct.
            //let prot = ctx.load::<IpProto>offset_of!(Ipv4Hdr, proto)).map_err(|_| 0)?;


            // In cgroup_skb programs, especially in container environments (e.g., Podman, Docker),
            // the Ethernet header is typically stripped by the time the packet reaches this hook.
            // This is because virtual interfaces (like veth) used by containers pass the packet
            // further into the networking stack, where layer 2 (Ethernet) data is no longer present.
            // Therefore, we start reading directly from offset 0, which corresponds to the IP header.
            let ip_hdr = ctx.load::<Ipv4Hdr>(0).map_err(|_| {
                warn!(&ctx, "Error loading Ipv4Hdr");
                0
            })?;

            let dst_addr = ip_hdr.dst_addr();
            let src_addr = ip_hdr.src_addr();

            match ip_hdr.proto {
                IpProto::Tcp => {
                    info!(&ctx, "TCP connection. Src: {} Dst: {}", src_addr, dst_addr);
                }
                IpProto::Udp => {
                    info!(&ctx, "UDP connection. Src: {} Dst: {}", src_addr, dst_addr);
                }
                IpProto::Icmp => {
                    info!(&ctx, "ICMP packet detected");
                }
                _ => {
                    info!(&ctx, "Unknown IP protocol");
                    return Ok(1)
                },
            }
            
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

    // Allow the packet to pass through
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
