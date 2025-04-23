#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};
use aya_log_ebpf::info;

#[cgroup_skb]
pub fn csp(ctx: SkBuffContext) -> i32 {
    match try_csp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_csp(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
