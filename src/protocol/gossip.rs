use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use blake3::Hasher;
use iroh::{Endpoint, EndpointId, PublicKey, SecretKey};
use iroh_gossip::api::GossipTopic;
use iroh_gossip::{Gossip, TopicId, api::Event};
use iroh_ping::Ping;
use log::{debug, error, info, warn};
use n0_future::StreamExt;
use pkarr::dns::{Name, rdata::TXT};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{Level, event, span};
use ucan::builder::UcanBuilder;

use crate::authentication::ucans::{NodeCapability, Validator};
use crate::common::types::{Signal, SignalMessage};
use crate::identity::IrohKeyMaterial;

pub struct SignalListener {
    pub topic_id: TopicId,
    pub validator: Validator,
    pub gossip: Gossip,
    pub bootstrap_peer_rx: Receiver<EndpointId>,
    pub signal_tx: Sender<Signal>,
}

impl SignalListener {
    pub async fn run(self) -> anyhow::Result<()> {
        let stream = self.gossip.subscribe(self.topic_id, vec![]).await?;

        tokio::spawn(SignalListener::handle_bootstrap_peers(
            self.topic_id.clone(),
            self.gossip.clone(),
            self.bootstrap_peer_rx,
        ));

        tokio::spawn(SignalListener::handle_gossip(
            self.topic_id.clone(),
            self.signal_tx.clone(),
            self.validator.clone(),
            stream,
        ));

        Ok(())
    }

    async fn handle_bootstrap_peers(
        topic_id: TopicId,
        gossip: Gossip,
        mut rx: Receiver<EndpointId>,
    ) -> anyhow::Result<()> {
        let mut active_peers = std::collections::HashSet::new();

        while let Some(peer_id) = rx.recv().await {
            if active_peers.insert(peer_id) {
                debug!(">>> DISCOVERY: Injecting new peer {} into mesh", peer_id);
                let _ = gossip.subscribe(topic_id, vec![peer_id]).await;
            }
        }

        Ok(())
    }

    async fn handle_gossip(
        topic_id: TopicId,
        tx: Sender<Signal>,
        validator: Validator,
        mut stream: GossipTopic,
    ) -> anyhow::Result<()> {
        info!("Gossip listener loop active for topic {}", topic_id);
        while let Some(res) = stream.next().await {
            let Ok(event) = res else {
                error!("Gossip stream error: {}", res.unwrap_err());
                continue;
            };
            if let Err(e) =
                SignalListener::handle_gossip_event(topic_id, validator.clone(), event, tx.clone())
                    .await
            {
                error!("Error handling gossip event: {}", e);
                continue;
            }
        }

        Ok(())
    }

    async fn handle_gossip_event(
        topic_id: TopicId,
        validator: Validator,
        event: iroh_gossip::api::Event,
        tx: Sender<Signal>,
    ) -> anyhow::Result<()> {
        match event {
            Event::Received(msg) => {
                let now = Validator::now_time();
                let decoded = decode_signal(&msg.content)?;

                validator.validate_signal(now, topic_id, &decoded).await?;
                tx.send(decoded.signal).await?;
            }
            Event::NeighborUp(peer) => info!(">>> MESH: Connected to neighbor {}", peer),
            Event::NeighborDown(peer) => info!(">>> MESH: Lost neighbor {}", peer),
            _ => {}
        };

        Ok(())
    }
}

// TODO: convert to struct w/ methods like SignalListener
pub async fn run_gossip_announcer(
    _endpoint: Endpoint,
    gossip: Gossip,
    topic_id: TopicId,
    mut bootstrap_peers: Receiver<EndpointId>,
    mut rx: Receiver<Signal>,
) -> anyhow::Result<()> {
    info!("starting gossip announcer {}", topic_id.to_string());
    let key_material = IrohKeyMaterial::new(SecretKey::from_str(
        "307f845d7665e1e37f63d271b7223c26db2ac71b40c0cb6ecc75dc2e2406d8ba",
    )?);
    let pub_did = IrohKeyMaterial::public_key_to_did(&PublicKey::from_str(
        "3d777ba633b421e0d4d231f063d20925b491344c02b81f7cbed5ee2e7d4dfccc",
    )?);
    let encoded_ucan = UcanBuilder::default()
        .issued_by(&key_material)
        .for_audience(&pub_did)
        .claiming_capabilities(&[
            NodeCapability::DeploymentNotify {
                namespace: "*".to_string(),
            }
            .to_ucan_capability_view(),
            NodeCapability::JoinTopic {
                topic_id: topic_id.to_string(),
            }
            .to_ucan_capability_view(),
            NodeCapability::EmitTopic {
                topic_id: topic_id.to_string(),
            }
            .to_ucan_capability_view(),
        ])
        .build()?
        .sign()
        .await?
        .encode()?;

    let (sender, receiver) = gossip.subscribe(topic_id, vec![]).await?.split();
    let sender_clone = sender.clone();
    let response_auth_ucan = encoded_ucan.clone();

    // 1. THE INJECTOR: Background task for new peers
    tokio::spawn(async move {
        while let Some(peer_id) = bootstrap_peers.recv().await {
            let _ = sender_clone.join_peers(vec![peer_id.into()]).await;
        }
    });

    tokio::spawn({
        let sender = sender.clone();
        let mut receiver = receiver; // The receiver half of the split stream
        let response_auth_ucan = response_auth_ucan.clone();

        async move {
            let mut has_neighbors = false;

            loop {
                tokio::select! {
                    // 1. WATCH MESH EVENTS
                    Some(event_res) = receiver.next() => {
                        if let Ok(Event::NeighborUp(peer)) = event_res {
                            info!(">>> ANNOUNCER: Mesh is LIVE. Neighbor {} connected.", peer);
                            has_neighbors = true;
                        }
                    },
                    // 2. WATCH FOR SIGNALS TO BROADCAST
                    Some(signal) = rx.recv() => {
                        if !has_neighbors {
                            warn!(">>> ANNOUNCER: Dropping signal - no neighbors yet. Consumer started too early?");
                            continue;
                        }

                        let Ok(encoded) = encode_signal(SignalMessage {
                            encoded_ucan: response_auth_ucan.clone(),
                            signal,
                        }) else { continue };

                        info!(">>> ANNOUNCER: Broadcasting deployment to active neighbors.");
                        let _ = sender.broadcast(encoded.into()).await;
                    }
                }
            }
        }
    });

    Ok(()) // Function returns immediately, tasks run in background
}

// TODO: convert to struct w/ methods like SignalListener
pub async fn start_gossip_discovery(
    endpoint: Endpoint,
    _gossip: Gossip,
    topic_id: TopicId,
    tx: Sender<EndpointId>,
) -> anyhow::Result<()> {
    let span = span!(Level::INFO, "Gossip Discovery");
    let _guard = span.enter();
    let topic_keypair = derive_topic_key(topic_id);
    let my_id = endpoint.id();
    let client = pkarr::Client::builder()
        .no_default_network()
        .relays(&["http://127.0.0.1:15411"])?
        .build()
        .unwrap();

    let pkarr_announcer = client.clone();
    let key_announcer = topic_keypair.clone();
    tokio::spawn(async move {
        let announcer_span = span!(Level::INFO, "Gossip Discover < Announcer");
        let _guard = announcer_span.enter();
        loop {
            let prefix = &my_id.to_string()[..8];
            let sub_label = format!("{}.{}", prefix, "_node"); // Unique to this node
            let text_inner = my_id.to_string();

            let mut retry_count = 0;
            'publish_attempt: loop {
                // 1. RESOLVE: Get the absolute latest state from the board
                let most_recent = pkarr_announcer
                    .resolve_most_recent(&key_announcer.public_key())
                    .await;

                // debug!("most recent: {:?}", most_recent);

                let mut builder = pkarr::SignedPacket::builder();
                let mut cas_timestamp = None;

                if let Some(packet) = most_recent {
                    event!(Level::DEBUG, "found packet");
                    cas_timestamp = Some(packet.timestamp());

                    // 2. MERGE: Add all existing records EXCEPT our own old one
                    for record in packet.all_resource_records() {
                        let record_name = record.name.to_string();
                        // We skip our own sub-label to avoid duplicates,
                        // but we MUST keep everyone else's.
                        if record_name != sub_label {
                            builder = builder.record(record.clone());
                        }
                    }
                }

                // 3. APPEND: Add our current record
                let text = TXT::new().with_string(&text_inner).unwrap();
                let signed_packet = builder
                    .txt(Name::new(&sub_label).unwrap(), text, 300)
                    .sign(&key_announcer);

                if let Ok(p) = signed_packet {
                    // 4. PUBLISH with CAS: This fails if the timestamp moved!
                    match pkarr_announcer.publish(&p, cas_timestamp).await {
                        Ok(_) => {
                            event!(Level::DEBUG, "Successfully updated board.");
                            break 'publish_attempt; // Success!
                        }
                        Err(e)
                            if e.to_string().contains("CAS")
                                || e.to_string().contains("conflict") =>
                        {
                            event!(
                                Level::WARN,
                                "CAS conflict (node joined/left). Retrying merge..."
                            );
                            retry_count += 1;
                            if retry_count > 5 {
                                break 'publish_attempt;
                            }
                            continue 'publish_attempt;
                        }
                        Err(e) => {
                            event!(Level::ERROR, "Publish error: {}", e);
                            break 'publish_attempt;
                        }
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });

    // 2. WATCHER: Poll the board for new peers
    // TODO: clean this up
    let tx_cloned = tx.clone();
    tokio::spawn(async move {
        loop {
            debug!(">>> DISCOVERY watcher running...");
            // Resolve the shared topic identity to see who else is on the board
            debug!(">>> DISCOVERY: 'my' peer id: {}", endpoint.clone().id());
            if let Some(signed) = client
                .clone()
                .resolve(&topic_keypair.clone().public_key())
                .await
            {
                info!("pkarr client initialized...");
                let mut records: Vec<String> = Vec::new();
                let tx_cloned_again = tx_cloned.clone();
                debug!(">>> DISCOVERY: 'my' peer id: {}", endpoint.clone().id());
                for record in signed.all_resource_records() {
                    debug!(">>> DISCOVERY/WATCHER record: {:?}", record);
                    records.push(record.name.to_string());
                    if let pkarr::dns::rdata::RData::TXT(txt) = &record.rdata {
                        // 2. In v5, txt is a helper that can be iterated or converted
                        // A TXT record can contain multiple strings (chunks)
                        let txt_clone = txt.clone();
                        let attributes = txt_clone.attributes();
                        let nth_key = attributes.keys().nth(0);
                        let Some(id_str) = nth_key else {
                            continue;
                        };

                        if let Ok(peer_id) = EndpointId::from_str(&(id_str.clone())) {
                            if peer_id != my_id {
                                debug!(">>> DISCOVERY: Found peer {}. Joining swarm...", peer_id);

                                let endpoint_cloned = endpoint.clone();
                                let value = tx_cloned_again.clone();
                                tokio::spawn(async move {
                                    if ping_peer(8000, endpoint_cloned, peer_id).await.is_ok() {
                                        debug!(">>> PING: {} peer latency was good", peer_id);
                                        if let Err(e) = value.send(peer_id.into()).await {
                                            error!("error adding discovered peer: {}", e);
                                        } else {
                                            info!(
                                                ">>> DISCOVERY successfully added peer {}",
                                                peer_id
                                            );
                                        }
                                    } else {
                                        debug!(">>> DISCOVERY: Peer {}, timed out", peer_id);
                                    }
                                });
                            }
                        } else {
                            error!("could not parse peer_id from id_str");
                        }
                    }
                }

                info!("current records: {:?}", records);
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });

    Ok(())
}

fn decode_signal(signal: &[u8]) -> anyhow::Result<SignalMessage> {
    Ok(postcard::from_bytes::<SignalMessage>(signal)?)
}

fn encode_signal(signal: SignalMessage) -> anyhow::Result<Vec<u8>> {
    Ok(postcard::to_stdvec(&signal)?)
}

pub fn derive_topic_id(namespace: &str, cluster_secret: &str) -> TopicId {
    let mut hasher = Hasher::new();

    // FIXME: replace with compile time salt
    hasher.update(b"slinger-deploym-v1");

    hasher.update(cluster_secret.as_bytes());
    hasher.update(namespace.as_bytes());

    let hash = hasher.finalize();
    TopicId::from(hash.as_bytes().clone())
}

fn derive_topic_key(topic_id: TopicId) -> pkarr::Keypair {
    pkarr::Keypair::from_secret_key(&topic_id.as_bytes())
}

pub async fn ping_peer(
    limit: u64,
    endpoint: iroh::Endpoint,
    peer_id: PublicKey,
) -> anyhow::Result<()> {
    let client = Ping::new();
    let pub_addr = iroh::EndpointAddr::new(peer_id);

    debug!(">>> PING: Sending magic ping to {}...", peer_id);

    match tokio::time::timeout(
        Duration::from_millis(limit as u64),
        client.ping(&endpoint, pub_addr),
    )
    .await
    {
        Ok(Ok(lat)) => {
            debug!(">>> PING: Success! Latency: {:?}", lat);
            return Ok(());
        }
        Ok(Err(e)) => error!("Error with ping {}", e),
        _ => {}
    };

    Err(anyhow!("ping failed or exceeded timeout - {}ms", 2000))
}
