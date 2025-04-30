use std::{net::Ipv4Addr, process::exit};

use anyhow::Context as _;
use aya::{
    maps::{MapData, RingBuf},
    programs::{links::CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
};
use csp_common::NetworkEventIpv4;
use libc::getuid;
use log::info;
#[rustfmt::skip]
use log::warn;
use logger::init_logger;
use podman::get_container_data;
use tracing::error;
use utils::{check_is_root_user, convert_protocol, set_mem_limit, wait_for_shutdown};

mod logger;
mod podman;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize the logger
    init_logger("info", "text");

    // This program must be run as root. Ebpf requires privileges
    let uid = unsafe { getuid() };
    if let Err(e) = check_is_root_user(uid) {
        error!("{}", e);
        exit(1);
    }

    let podman = podman::get_podman_client();
    let containers = podman::list_containers(&podman, true).await?;
    let data = get_container_data(&podman, containers).await?;

    if data.is_empty() {
        warn!("No containers found. Please make sure you have running containers. Hint: $ podman ps -a");
        return Ok(());
    }

    set_mem_limit();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/csp"
    )))?;

    // if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
    //     // This can happen if you remove all log statements from your eBPF program.
    //     warn!("failed to initialize eBPF logger: {}", e);
    // }

    let program: &mut CgroupSkb = ebpf.program_mut("csp").unwrap().try_into()?;
    program.load()?;

    for container_data in data {
        let cgroup_file = std::fs::File::open(&container_data.cgroup_path)
            .with_context(|| format!("{}", container_data.cgroup_path))?;

        program.attach(
            &cgroup_file,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::default(),
        )?;
        info!("Sniffing container traffic: {}", container_data.name);
    }

    let network_event_ipv4_rinf_map = ebpf
        .take_map("NETWORK_EVENT_IPV4")
        .ok_or_else(|| anyhow::anyhow!("Failed to find ring buffer NETWORK_EVENT_IPV4 map"))?;

    let ring_buf_ipv4 = RingBuf::try_from(network_event_ipv4_rinf_map)?;

    // let network_event_ipv6_rinf_map = ebpf
    //     .take_map("NETWORK_EVENT_IPV6")
    //     .ok_or_else(|| anyhow::anyhow!("Failed to find ring buffer NETWORK_EVENT_IPV6 map"))?;

    //let ring_buf_ipv6 = RingBuf::try_from(network_event_ipv6_rinf_map)?;

    tokio::spawn(async move { process_event(ring_buf_ipv4).await });
    //tokio::spawn(async move { process_ipv6_event(ring_buf_ipv6).await });

    let _ = wait_for_shutdown().await;

    Ok(())
}

// async fn process_ipv6_event(mut ring_buf: RingBuf<MapData>) -> Result<(), anyhow::Error> {
//     loop {
//         while let Some(event) = ring_buf.next() {
//             // Get the data from the event
//             let data = event.as_ref();

//             // Make sure the data is the correct size
//             if data.len() == std::mem::size_of::<NetworkEventIpv6>() {
//                 let event: &NetworkEventIpv6 = unsafe { &*(data.as_ptr() as *const NetworkEventIpv6) };
//                 // Process the event
//                 info!(
//                     "Received event: src_addr: {}, dst_addr: {}, protocol: {}",
//                     Ipv6Addr::from(event.src_addr),
//                     Ipv6Addr::from(event.dst_addr),
//                     convert_protocol(event.protocol)
//                 );
//             }
//         }

//         // Sleep for a while
//         tokio::time::sleep(std::time::Duration::from_millis(100)).await;
//     }
// }

async fn process_event(mut ring_buf: RingBuf<MapData>) -> Result<(), anyhow::Error> {
    loop {
        while let Some(event) = ring_buf.next() {
            // Get the data from the event
            let data = event.as_ref();

            // Make sure the data is the correct size
            if data.len() == std::mem::size_of::<NetworkEventIpv4>() {
                let event: &NetworkEventIpv4 =
                    unsafe { &*(data.as_ptr() as *const NetworkEventIpv4) };
                // Process the event
                info!(
                    "Received event: src_addr: {}, dst_addr: {}, protocol: {}",
                    Ipv4Addr::from(event.src_addr),
                    Ipv4Addr::from(event.dst_addr),
                    convert_protocol(event.protocol)
                );
            }
        }

        // Sleep for a while
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
