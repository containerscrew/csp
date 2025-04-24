use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::{maps::{MapData, RingBuf}, programs::{links::CgroupAttachMode, CgroupSkb, CgroupSkbAttachType}};
use csp_common::NetworkEvent;
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use podman::get_container_data;
use utils::{convert_protocol, wait_for_shutdown};


mod podman;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let podman = podman::get_podman_client();
    let containers = podman::list_containers(&podman, true).await?;
    let data = get_container_data(&podman,containers).await?;

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/csp"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

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
        info!(
            "Monitoring traffic for container {} with cgroup path {} and id {}",
            container_data.name, container_data.cgroup_path, container_data.id
        );
    }

    let network_event_ring_map = ebpf
    .take_map("NETWORK_EVENT")
    .ok_or_else(|| anyhow::anyhow!("Failed to find ring buffer NETWORK_EVENT map"))?;

    let ring_buf = RingBuf::try_from(network_event_ring_map)?;

    tokio::spawn(async move { process_event(ring_buf).await });

    let _ = wait_for_shutdown().await;

    Ok(())
}

async fn process_event(mut ring_buf: RingBuf<MapData>) -> Result<(), anyhow::Error> {
    loop {
        while let Some(event) = ring_buf.next() {
            // Get the data from the event
            let data = event.as_ref();

            // Make sure the data is the correct size
            if data.len() == std::mem::size_of::<NetworkEvent>() {
                let event: &NetworkEvent = unsafe { &*(data.as_ptr() as *const NetworkEvent) };
                // Process the event
                info!(
                    "Received event: src_addr: {}, dst_addr: {}, protocol: {}",
                    Ipv4Addr::from(event.src_addr), Ipv4Addr::from(event.dst_addr), convert_protocol(event.protocol)
                );
            }
        }

        // Sleep for a while
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
