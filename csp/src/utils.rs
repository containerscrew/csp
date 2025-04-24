use log::{info, warn};
use tokio::signal;

pub async fn wait_for_shutdown() -> anyhow::Result<()> {
    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    warn!("You press Ctrl-C, shutting down nflux...");
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
