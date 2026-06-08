use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bollard::{errors::Error, query_parameters::ListContainersOptionsBuilder, Docker};
use tokio::{sync::watch::Sender, time::sleep};

use crate::{
    pp::{self, PP},
    provider::IpType,
};

pub async fn spawn_docker_domain_scanner(
    static_domains: HashMap<IpType, Vec<String>>,
    docker_sock: String,
    domains_tx: &mut Sender<HashMap<IpType, Vec<String>>>,
    running: Arc<AtomicBool>,
    ppfmt: &PP,
) -> Result<(), Error> {
    let docker = Docker::connect_with_host(docker_sock.as_str())?;

    let mut docker_domains = scan_and_publish_once(
        &docker,
        &static_domains,
        HashSet::default(),
        &mut domains_tx.clone(),
    )
    .await?;

    let domains_tx = domains_tx.clone();
    let ppfmt_owned = ppfmt.clone();

    tokio::spawn(async move {
        while running.load(Ordering::SeqCst) {
            docker_domains = match scan_and_publish_once(
                &docker,
                &static_domains,
                docker_domains.clone(),
                &mut domains_tx.clone(),
            )
            .await
            {
                Ok(dd) => dd,
                Err(e) => {
                    ppfmt_owned.errorf(
                        pp::EMOJI_ERROR,
                        &format!("DOCKER unable to scan: {}", e.to_string()),
                    );

                    docker_domains
                }
            };

            sleep(Duration::from_secs(5)).await;
        }
    });

    return Ok(());
}

async fn scan_and_publish_once(
    docker: &Docker,
    static_domains: &HashMap<IpType, Vec<String>>,
    docker_domains: HashSet<String>,
    domains_tx: &mut Sender<HashMap<IpType, Vec<String>>>,
) -> Result<HashSet<String>, Error> {
    let list_options = ListContainersOptionsBuilder::default()
        .all(true)
        .filters(&HashMap::from([(
            "status",
            vec!["created", "restarting", "running"],
        )]))
        .build();

    let list = docker.list_containers(Some(list_options)).await?;

    let new_docker_domains: HashSet<String> = list
        .iter()
        .filter_map(|c| {
            c.labels
                .as_ref()
                .and_then(|labels| labels.get("ddns.domain"))
        })
        .cloned()
        .collect();

    if docker_domains == new_docker_domains {
        return Ok(docker_domains);
    }

    let mut new_domains = static_domains.clone();

    new_domains
        .entry(IpType::V4)
        .or_default()
        .extend(new_docker_domains.clone());

    new_domains
        .entry(IpType::V6)
        .or_default()
        .extend(new_docker_domains.clone());

    domains_tx.send_replace(new_domains);

    return Ok(new_docker_domains);
}
