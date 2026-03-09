use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use iroh::{
    Endpoint, EndpointAddr, EndpointId,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, EndpointHooks},
    protocol::{AcceptError, ProtocolHandler},
};
use log::{debug, error, info};
use n0_error::{AnyError, Meta};
use tokio::sync::{Mutex, Notify, OnceCell};
use tracing::{Level, event, span};

use crate::authentication::ucans::Validator;

pub const ALPN: &[u8] = b"slinger/auth/0";
const MAX_STREAM_SIZE: usize = 5120;
pub const CLOSE_ACCEPTED: u32 = 1;
pub const CLOSE_DENIED: u32 = 403;

#[derive(Debug, Clone)]
pub struct Authentication {
    pub ucan_validator: Validator,
    pub encoded_ucan: String,
    pub allowed_remotes: Arc<Mutex<HashMap<EndpointId, String>>>,
    pub auth_notifiers: Arc<Mutex<HashMap<EndpointId, Arc<Notify>>>>,
    pub endpoint: Arc<OnceCell<Endpoint>>,
}

impl EndpointHooks for Authentication {
    async fn after_handshake<'a>(
        &'a self,
        conn: &'a iroh::endpoint::ConnectionInfo,
    ) -> AfterHandshakeOutcome {
        // Inbound hook/intercept
        if conn.alpn() == iroh_ping::ALPN || conn.alpn() == ALPN {
            return AfterHandshakeOutcome::Accept;
        }

        match self.allowed_remotes.lock().await.get(&conn.remote_id()) {
            Some(_) => AfterHandshakeOutcome::Accept,
            None => AfterHandshakeOutcome::Reject {
                error_code: CLOSE_DENIED.into(),
                reason: b"has not authenticated yet".to_vec(),
            },
        }
    }

    async fn before_connect<'a>(
        &'a self,
        remote_addr: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        let peer_id = remote_addr.id;

        // 1. If it's an Auth or Ping connection, let it through immediately
        if alpn == ALPN || alpn == iroh_ping::ALPN {
            return BeforeConnectOutcome::Accept;
        }

        // 2. Check if already authenticated
        if self.allowed_remotes.lock().await.contains_key(&peer_id) {
            return BeforeConnectOutcome::Accept;
        }

        // 3. Get or create a notifier for this peer
        let notifier = {
            let mut notifiers = self.auth_notifiers.lock().await;
            if let Some(n) = notifiers.get(&peer_id) {
                n.clone()
            } else {
                let n = Arc::new(Notify::new());
                notifiers.insert(peer_id, n.clone());

                // 4. No Auth task is running for this peer, so spawn one!
                let this = self.clone();
                tokio::spawn(async move {
                    let _ = this.perform_outbound_auth(peer_id).await;

                    // 5. Cleanup: notify anyone waiting and remove from map
                    let n_to_trigger = this.auth_notifiers.lock().await.remove(&peer_id);
                    if let Some(n) = n_to_trigger {
                        n.notify_waiters();
                    }
                });
                n
            }
        };

        // 6. WAIT for the auth task to finish before allowing the Gossip connection to proceed
        debug!(
            ">>> HOOKS: Gossip connection for {} waiting for Auth...",
            peer_id
        );
        notifier.notified().await;

        BeforeConnectOutcome::Accept
    }
}

impl ProtocolHandler for Authentication {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = connection.accept_bi().await?;
        let now_time = Validator::now_time();

        // 1. READ LENGTH (4 bytes)
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .map_err(|e| AcceptError::User {
                source: AnyError::from_std(e),
                meta: Meta::default(),
            })?;
        let ucan_len = u32::from_be_bytes(len_buf) as usize;

        // 2. READ EXACT UCAN
        let mut ucan_buf = vec![0u8; ucan_len];
        recv.read_exact(&mut ucan_buf)
            .await
            .map_err(|e| AcceptError::User {
                source: AnyError::from_std(e),
                meta: Meta::default(),
            })?;
        debug!("AUTHENTICATION/INBOUND ucan read");
        let encoded_ucan = String::from_utf8(ucan_buf).map_err(|_| AcceptError::User {
            source: AnyError::from_anyhow(anyhow!("invalid utf8")),
            meta: Meta::default(),
        })?;

        debug!("AUTHENTICATION/INBOUND ucan validate");
        // 3. VALIDATE & RESPOND (Write our own length-prefixed UCAN)
        self.ucan_validator
            .validate_new_connetion(now_time, encoded_ucan.clone())
            .await
            .map_err(|e| {
                error!("error validating ucan: {}", e);
                AcceptError::NotAllowed {
                    meta: Meta::default(),
                }
            })?;

        debug!("AUTHENTICATION/INBOUND ucan send");
        let my_ucan_bytes = self.encoded_ucan.as_bytes();
        let my_len_bytes = (my_ucan_bytes.len() as u32).to_be_bytes();

        send.write_all(&my_len_bytes)
            .await
            .map_err(|e| AcceptError::User {
                source: AnyError::from_std(e),
                meta: Meta::default(),
            })?;
        send.write_all(my_ucan_bytes)
            .await
            .map_err(|e| AcceptError::User {
                source: AnyError::from_std(e),
                meta: Meta::default(),
            })?;

        send.finish().map_err(|e| AcceptError::User {
            source: AnyError::from_std(e),
            meta: Meta::default(),
        })?;

        let _ = send.stopped().await;

        debug!("AUTHENTICATION/INBOUND adding to remotes");
        self.allowed_remotes
            .lock()
            .await
            .insert(connection.remote_id(), encoded_ucan);
        Ok(())
    }
}

impl Authentication {
    async fn perform_outbound_auth(&self, remote_id: EndpointId) -> anyhow::Result<()> {
        // let span = span!(
        //     Level::INFO,
        //     "Proto>Auth>Hook>Outbound",
        //     remote_peer = remote_id.to_string()
        // );
        // let _guard = span.enter();
        log::debug!(
            namespace = "proto/auth/hook/outbound";
            "initiating auth {remote_id:?}",
        );
        let endpoint = self
            .endpoint
            .get()
            .ok_or_else(|| anyhow!("Endpoint not ready"))?;
        let conn = endpoint.connect(remote_id, ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        event!(Level::DEBUG, "writing ucan");
        // 1. WRITE: Length + UCAN
        let my_bytes = self.encoded_ucan.as_bytes();
        send.write_all(&(my_bytes.len() as u32).to_be_bytes())
            .await?;
        send.write_all(my_bytes).await?;

        event!(Level::DEBUG, "reading len of remote's ucan");
        // 2. READ: Length + UCAN
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await?;
        let their_len = u32::from_be_bytes(len_buf) as usize;

        event!(Level::DEBUG, "reading remote's ucan");
        let mut their_buf = vec![0u8; their_len];
        recv.read_exact(&mut their_buf).await?;
        let their_ucan = String::from_utf8(their_buf)?;

        send.finish()?;
        // 2. Wait for the final flush
        let _ = send.stopped().await;

        event!(Level::DEBUG, "validating remote's ucan");
        // 3. VALIDATE
        let now = Validator::now_time();
        self.ucan_validator
            .validate_new_connetion(now, their_ucan.clone())
            .await?;

        self.allowed_remotes
            .lock()
            .await
            .insert(remote_id, their_ucan);
        event!(Level::INFO, "auth successfull",);
        Ok(())
    }
}
