use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bollard::{errors::Error, query_parameters::ListContainersOptionsBuilder, Docker};
use tokio::{
    sync::watch::{Receiver, Sender},
    time::sleep,
};

use crate::{
    cloudflare::CloudflareHandle,
    config::AppConfig,
    notifier::{CompositeNotifier, Message},
    pp::{self, PP},
    provider::IpType,
};

pub async fn spawn_domain_cleanup(
    config: &AppConfig,
    domains_rx: &mut Receiver<HashMap<IpType, Vec<String>>>,
    running: Arc<AtomicBool>,
    ppfmt: &PP,
    handle: &CloudflareHandle,
    notifier: &CompositeNotifier,
) -> Result<(), Error> {
    if !config.delete_on_stop || config.legacy_mode {
        return Ok(());
    }

    let ppfmt_owned = ppfmt.clone();
    let handle_owned = handle.clone();
    let notifier_owned = notifier.clone();
    let mut domains_rx = domains_rx.clone();

    tokio::spawn(async move {
        let mut current_domains = domains_rx.borrow_and_update().clone();
        while running.load(Ordering::SeqCst) {
            loop {
                if !running.load(Ordering::SeqCst) {
                    return;
                }

                match domains_rx.has_changed() {
                    Ok(true) => break, // Changed
                    Ok(false) => {}    // No change yet
                    Err(_) => return,  // channel closed
                }

                sleep(Duration::from_secs(1)).await;
            }

            let mut messages = Vec::new();
            let new_domains = domains_rx.borrow_and_update().clone();

            for (ip_type, old_domains_list) in current_domains.iter() {
                let record_type = ip_type.record_type();
                let new_domains_list = new_domains.get(ip_type).unwrap_or(old_domains_list);
                let domains_diff = old_domains_list
                    .into_iter()
                    .filter(|d| !new_domains_list.contains(d));

                for domain_str in domains_diff {
                    // Use the owned handle
                    if let Some(zone_id) = handle_owned
                        .zone_id_of_domain(domain_str, &ppfmt_owned)
                        .await
                    {
                        handle_owned
                            .final_delete(&zone_id, domain_str, record_type, &ppfmt_owned)
                            .await;
                        messages.push(Message::new_ok(&format!(
                            "Deleted records for {domain_str}"
                        )));
                    }
                }
            }

            let msg = Message::merge(messages);
            notifier_owned.send(&msg).await;

            current_domains = new_domains;
        }
    });

    return Ok(());
}

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
