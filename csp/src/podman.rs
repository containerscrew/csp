use podman_api::{models::ListContainer, opts::ContainerListOpts, Podman};


#[derive(Debug)]
#[allow(dead_code)]
pub struct ContainerData {
    pub id: String,
    pub cgroup_path: String,
    pub name: String,
}

pub fn get_podman_client() -> Podman {
    Podman::unix("/run/user/1000/podman/podman.sock")
}

pub async fn list_containers(podman: &Podman, all: bool) -> Result<Vec<ListContainer>, anyhow::Error>{
    let opts = ContainerListOpts::builder()
        .all(all)
        .build();

    let containers = podman.containers().list(&opts).await?;
    Ok(containers)
}

pub async fn return_container_data(podman: &Podman, containers: Vec<ListContainer>) -> Result<Vec<ContainerData>, anyhow::Error> {

    let mut available_containers = Vec::new();

    for data in containers {
        if let Some(id) = data.id {
            let container = podman.containers().get(&id);

            let inspect = container.inspect().await?;

            if let Some(state) = inspect.state {
                if let Some(cgroup_path) = state.cgroup_path {
                    let container_data = ContainerData {
                        id: id,
                        cgroup_path: format!("/sys/fs/cgroup{}", cgroup_path),
                        name: data.names.unwrap_or_default().join(","),
                    };
                    available_containers.push(container_data);
                } else {
                    // cgroup is mandatory to sniff traffic
                    // without cgroup, we cannot sniff traffic
                    break;
                }
            }
        }
    }
    Ok(available_containers)
}
