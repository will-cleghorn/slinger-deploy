use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};

use iroh::{
    Endpoint, EndpointId, PublicKey, RelayConfig, RelayUrl, SecretKey, address_lookup,
    protocol::Router,
};
use iroh_blobs::{
    BlobsProtocol,
    api::{
        Store,
        downloader::{Downloader, Shuffled},
    },
    store::mem::MemStore,
    ticket::BlobTicket,
};
use iroh_gossip::Gossip;
use log::{debug, info};
use tokio::sync::{
    Mutex, OnceCell,
    mpsc::{self, Receiver},
};
use tracing::{Level, span};
use ucan::builder::UcanBuilder;

use crate::{
    authentication::ucans::NodeCapability,
    identity::IrohKeyMaterial,
    protocol::{
        authentication::{self as proto_auth, Authentication},
        gossip::{SignalListener, start_gossip_discovery},
    },
};
use crate::{authentication::ucans::Validator, identity::verify_deployment};
use crate::{
    common::types::{Signal, SignedDeployment},
    protocol::gossip::derive_topic_id,
};

pub struct Consumer {
    router: Router,
    signal_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    gossip_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    signal_listener_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Consumer {
    pub async fn new(
        cluster_secret: &str,
        namespace: &str,
        producer_pub_key: &str,
        tier: u8,
    ) -> anyhow::Result<Self> {
        let span = span!(Level::INFO, "Consumer::new");
        let _guard = span.enter();
        // let (outgoing_hook, auth_task) = outgoing(encoded_ucan);
        let mut rng = rand::rng();
        let secret_key = SecretKey::generate(&mut rng);
        let key_material = IrohKeyMaterial::new(SecretKey::from_str(
            "307f845d7665e1e37f63d271b7223c26db2ac71b40c0cb6ecc75dc2e2406d8ba",
        )?);
        let pub_did = IrohKeyMaterial::public_key_to_did(&key_material.secret_key.public());
        let encoded_ucan = UcanBuilder::default()
            .issued_by(&key_material)
            .for_audience(&pub_did)
            .claiming_capabilities(&[
                NodeCapability::DeploymentNotify {
                    namespace: "*".to_string(),
                }
                .to_ucan_capability_view(),
                NodeCapability::JoinTopic {
                    topic_id: "*".to_string(),
                }
                .to_ucan_capability_view(),
                NodeCapability::EmitTopic {
                    topic_id: derive_topic_id(namespace, cluster_secret).to_string(),
                }
                .to_ucan_capability_view(),
            ])
            .build()?
            .sign()
            .await?
            .encode()?;

        let hashmap: HashMap<PublicKey, String> = HashMap::new();
        let authentication = Authentication {
            ucan_validator: Validator::new(key_material.secret_key.public()),
            encoded_ucan,
            allowed_remotes: Arc::new(Mutex::new(hashmap)),
            endpoint: Arc::new(OnceCell::new()),
            auth_notifiers: Arc::new(Mutex::new(HashMap::new())),
        };

        let local_relay_url = RelayUrl::from_str("http://127.0.0.1:3340")?;
        let relay_config = RelayConfig {
            url: local_relay_url,
            quic: None,
        };
        let endpoint = Endpoint::builder()
            .hooks(authentication.clone())
            .secret_key(secret_key)
            .relay_mode(iroh::RelayMode::Custom(relay_config.into()))
            .bind()
            .await?;

        authentication
            .endpoint
            .set(endpoint.clone())
            .expect("only set once");

        let _ = endpoint.online().await;

        let (download_manager, blobs) =
            DownloadManager::new(&endpoint, "./consumed", producer_pub_key).await?;

        let gossip = Gossip::builder().spawn(endpoint.clone());
        let ping = iroh_ping::Ping::new();
        let router = Router::builder(endpoint.clone())
            .accept(proto_auth::ALPN, authentication)
            .accept(iroh_ping::ALPN, ping)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .spawn();
        let topic_id = derive_topic_id(namespace, cluster_secret);
        let (tx, rx) = mpsc::channel::<Signal>(32);
        let (endpoint_tx, endpoint_rx) = mpsc::channel::<EndpointId>(32);

        let gossip_handle = tokio::spawn(start_gossip_discovery(
            endpoint.clone(),
            gossip.clone(),
            topic_id,
            endpoint_tx,
        ));

        let tier_min = match tier {
            0 => None,
            other => Some(other - 1),
        };

        let validator = Validator::new(PublicKey::from_str(producer_pub_key)?);

        tracing::info!(">>> CONSUMER: starting gossip/signal listener");
        let signal_listener_handle = tokio::spawn(SignalListener::run(SignalListener {
            topic_id: topic_id.clone(),
            validator: validator.clone(),
            gossip: gossip.clone(),
            bootstrap_peer_rx: endpoint_rx,
            signal_tx: tx.clone(),
        }));

        Ok(Consumer {
            signal_handle: tokio::spawn(Consumer::run_signal_manager(
                tier_min,
                download_manager,
                rx,
            )),
            signal_listener_handle,
            gossip_handle,
            router,
        })
    }

    async fn run_signal_manager(
        deployer_tier_min: Option<u8>,
        download_manager: DownloadManager,
        mut rx: Receiver<Signal>,
    ) -> anyhow::Result<()> {
        while let Some(signal) = rx.recv().await {
            info!("signal recieved: {:?}", signal);
            match signal {
                Signal::Deploy(deployment) => {
                    let dm = download_manager.clone();
                    if deployment.deployment.deployer_tier == deployer_tier_min {
                        tokio::spawn(async move {
                            if let Err(e) = dm.retrieve_deployment(deployment).await {
                                eprintln!("Failed to deploy: {e}");
                            }
                        });
                    }

                    continue;
                }
                Signal::Heartbeat(_status) => {
                    // TODO: impl
                    continue;
                }
                Signal::Revoke {
                    node_id: _,
                    reason: _,
                } => {
                    // TODO: pass signal to auth proto to deny the peers connection
                    continue;
                }
            }
        }
        Ok(())
    }

    pub async fn wait_for_exit(self) -> anyhow::Result<()> {
        tokio::select! {
            res = self.signal_handle => {
                println!("Signal manager exited");
                let _ = res??;
            },
            res = self.gossip_handle => {
                println!("Gossip listener exited");
                let _ = res??;
            },
        }

        self.router.shutdown().await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct DownloadManager {
    store: Store,
    downloader: Downloader,
    producer_pub_key: PublicKey, // Parsed type
    download_directory: PathBuf, // Path type
}

impl DownloadManager {
    pub async fn new(
        endpoint: &Endpoint,
        download_directory: impl Into<PathBuf>, // Accept anything that can become a PathBuf
        producer_pub_key_str: &str,
    ) -> anyhow::Result<(Self, BlobsProtocol)> {
        let producer_pub_key = producer_pub_key_str.parse()?; // Parse once
        let mstore = MemStore::new();
        let blobs = BlobsProtocol::new(&mstore, None);
        let downloader = mstore.downloader(endpoint);

        Ok((
            DownloadManager {
                download_directory: download_directory.into(),
                store: blobs.store().clone(),
                downloader,
                producer_pub_key,
            },
            blobs,
        ))
    }

    pub async fn download_artifact(
        &self,
        artifact_ticket: BlobTicket,
        path: PathBuf,
    ) -> anyhow::Result<()> {
        let endpoint_id = artifact_ticket.addr().id;

        self.downloader
            .download(artifact_ticket.hash(), Shuffled::new(vec![endpoint_id]))
            .await?;
        self.store
            .blobs()
            .export(artifact_ticket.hash(), std::path::absolute(path)?)
            .await?;

        Ok(())
    }

    pub async fn retrieve_deployment(&self, deployment: SignedDeployment) -> anyhow::Result<()> {
        verify_deployment(&self.producer_pub_key, &deployment)?;
        debug!("deployment verified");

        let ticket: BlobTicket = deployment.deployment.ticket.parse()?;
        let deployment_download_path =
            self.deployment_path(deployment.deployment.version.as_str())?;

        self.download_artifact(ticket, deployment_download_path)
            .await?;

        Ok(())
    }

    pub fn deployment_path(&self, version: &str) -> anyhow::Result<PathBuf> {
        // join() is safer than format!()
        let path = self.download_directory.join(version);
        Ok(std::path::absolute(path)?)
    }
}
