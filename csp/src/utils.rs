use libc::setrlimit;
use log::{info, warn};
use tokio::signal;

pub async fn wait_for_shutdown() -> anyhow::Result<()> {
    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    warn!("You press Ctrl-C, shutting down nflux...");
    Ok(())
}

/// is_root_user checks if the current user who runs the program is root.
/// Avoid running nflux as uid != 0 (root). Ebpf requires privileges
pub fn check_is_root_user(uid: u32) -> Result<(), String> {
    if uid != 0 {
        return Err(
            "This program must be run as root. Try: $ sudo nflux -i iface-name".to_string(),
        );
    }
    Ok(())
}

/// convert_protocol converts the protocol number to a string.
pub fn convert_protocol(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    }
}

/// set_mem_limit bumps the memlock rlimit to infinity.
/// Bump the memlock rlimit. This is needed for older kernels that don't use the
/// new memcg based accounting, see https://lwn.net/Articles/837122/
pub fn set_mem_limit() {
    // Bump the memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {}", ret);
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_convert_protocol() {
        assert_eq!(convert_protocol(1), "icmp");
        assert_eq!(convert_protocol(6), "tcp");
        assert_eq!(convert_protocol(17), "udp");
        assert_eq!(convert_protocol(255), "unknown");
    }
}
