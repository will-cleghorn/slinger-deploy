use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use iroh::{Endpoint, protocol::Router};
use iroh::{EndpointId, RelayConfig, RelayUrl, SecretKey};
use iroh_blobs::BlobsProtocol;
use iroh_blobs::store::mem::MemStore;
use iroh_blobs::ticket::BlobTicket;
use iroh_gossip::Gossip;
use log::{error, info};
use tokio::sync::mpsc::{self};
use tokio::sync::{Mutex, OnceCell};
use ucan::time::now;

use crate::authentication::ucans::Validator;
use crate::protocol::authentication::{self as proto_auth, Authentication};
use crate::protocol::gossip::{derive_topic_id, start_gossip_discovery};
use crate::{
    common::types::{Deployment, Signal},
    identity::sign_deployment,
    protocol::gossip::run_gossip_announcer,
};

pub struct Producer {
    router: Router,
    announcer_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    deployer_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    gossip_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    pub endpoint: Endpoint,
    // store: MemStore,
    // artifact_path: PathBuf,
    // gossip: Gossip,
}

impl Producer {
    pub async fn new(
        pk: SecretKey,
        cluster_secret: &str,
        namespace: &str,
        artifact_path: PathBuf,
        encoded_ucan: String,
    ) -> anyhow::Result<Self> {
        let authentication = Authentication {
            ucan_validator: Validator::new(pk.public()),
            encoded_ucan: encoded_ucan.clone(),
            allowed_remotes: Arc::new(Mutex::new(HashMap::new())),
            endpoint: Arc::new(OnceCell::new()),
            auth_notifiers: Arc::new(Mutex::new(HashMap::new())),
        };

        let relay_config = RelayConfig {
            url: RelayUrl::from_str("http://127.0.0.1:3340")?,
            quic: None,
        };
        let endpoint = Endpoint::builder()
            .hooks(authentication.clone())
            .secret_key(pk)
            .relay_mode(iroh::RelayMode::Custom(relay_config.into()))
            .bind()
            .await?;

        let gossip = Gossip::builder().spawn(endpoint.clone());
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);

        let (gossip_discovery_tx, gossip_discover_rx) = mpsc::channel::<EndpointId>(32);
        let (signal_tx, signal_rx) = mpsc::channel::<Signal>(32);
        let topic_id = derive_topic_id(namespace, cluster_secret);
        let ping = iroh_ping::Ping::new();
        let router = Router::builder(endpoint.clone())
            .accept(iroh_ping::ALPN, ping)
            .accept(proto_auth::ALPN, authentication)
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .spawn();

        let _ = endpoint.online().await;

        let endpoint_clone = endpoint.clone();
        let announcer_gossip = gossip.clone();
        let gossip_handle = tokio::spawn(start_gossip_discovery(
            endpoint.clone(),
            gossip.clone(),
            topic_id,
            gossip_discovery_tx,
        ));
        let announcer_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(4)).await;
            run_gossip_announcer(
                endpoint_clone,
                announcer_gossip.clone(),
                topic_id,
                gossip_discover_rx,
                signal_rx,
            )
            .await
        });

        let abs_path = std::path::absolute(&artifact_path)?;
        let tag = store.blobs().add_path(abs_path).await?;

        let ticket = BlobTicket::new(endpoint.addr(), tag.hash, tag.format);

        let deployment = Deployment {
            version: "0.1.0".to_string(),
            ticket: ticket.to_string(),
            created_date: 0,
            deployer_tier: None,
        };

        let endpoint_actual = endpoint.clone();
        let deployer_handle = tokio::spawn(async move {
            let deployment_endpoint = endpoint.clone();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                let mut new_deployment = deployment.clone();
                new_deployment.created_date = now();
                let signed_deployment =
                    sign_deployment(&deployment_endpoint.secret_key(), new_deployment)?;
                if let Err(e) = signal_tx.send(Signal::Deploy(signed_deployment)).await {
                    error!("error sending deployment to gossip announcer: {}", e);
                    break;
                }

                info!("deployment snet to gossip_announcer");
            }
            Ok(())
        });

        Ok(Producer {
            router,
            announcer_handle,
            endpoint: endpoint_actual,
            // store,
            // artifact_path,
            // gossip: gossip.clone(),
            gossip_handle,
            deployer_handle,
        })
    }

    pub async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.announcer_handle.await?;
        let _ = self.deployer_handle.await?;
        let _ = self.gossip_handle.await?;
        let _ = self.router.shutdown().await?;
        Ok(())
    }
}
