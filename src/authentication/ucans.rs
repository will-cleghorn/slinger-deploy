use core::fmt;
use std::{
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, anyhow};
use iroh::{EndpointId, PublicKey};
use iroh_gossip::TopicId;
use log::info;
use serde_json::json;
use ucan::{
    Ucan,
    capability::{Resource, ResourceUri},
    chain::{CapabilityInfo, ProofChain},
    crypto::did::DidParser,
};

use crate::{common::types::SignalMessage, identity::IrohKeyMaterial};

#[derive(Clone, Debug)]
pub struct Validator {
    store: ucan::store::MemoryStore,
    root_endpoint_id: EndpointId,
}

impl Validator {
    pub fn new(root_endpoint_id: EndpointId) -> Self {
        Validator {
            store: ucan::store::MemoryStore::default(),
            root_endpoint_id,
        }
    }

    pub async fn validate_signal(
        &self,
        now_time: u64,
        topic_id: TopicId,
        signal: &SignalMessage,
    ) -> Result<()> {
        let encoded_ucan = signal.encoded_ucan.clone();
        let ucan = Ucan::from_str(encoded_ucan.as_str())
            .map_err(|e| anyhow!("Failed to parse UCAN JWT: {}", e))?;

        info!("ucan: {:?}", ucan);
        if ucan.is_expired(Some(now_time)) {
            return Err(anyhow!("Authorization Token Expired"));
        }
        if ucan.is_too_early() {
            return Err(anyhow!("Authorization Token used too early"));
        }

        let chain = ProofChain::from_ucan(
            ucan,
            Some(now_time),
            &mut DidParser::new(SLINGER_SUPPORTED_KEYS),
            &self.store,
        )
        .await?;

        let root_pub_key = PublicKey::from_str(&self.root_endpoint_id.to_string())?;
        let expected_root_did = IrohKeyMaterial::public_key_to_did(&root_pub_key);

        if get_root_issuer(&chain) != expected_root_did {
            return Err(anyhow!("Unauthorized Root: {}", chain.ucan().issuer()));
        }

        let cap_emit_topic = NodeCapability::EmitTopic {
            topic_id: topic_id.to_string(),
        }
        .to_ucan_capability_view();

        let has_emit_topic = chain
            .reduce_capabilities(&SlingerSemantics)
            .iter()
            .any(|cap| cap.capability.enables(&cap_emit_topic));

        if !has_emit_topic {
            return Err(anyhow!(
                "Token does not authorize emiting to topic - {:?}",
                cap_emit_topic
            ));
        }

        Ok(())
    }

    pub async fn validate_new_connetion(
        &self,
        now_time: u64,
        encoded_ucan: String,
    ) -> Result<Vec<CapabilityInfo<SlingerScope, SlingerAbility>>> {
        let ucan = Ucan::from_str(encoded_ucan.as_str())
            .map_err(|e| anyhow!("Failed to parse UCAN JWT: {}", e))?;

        if ucan.is_expired(Some(now_time)) {
            return Err(anyhow!("Authorization Token Expired"));
        }
        if ucan.is_too_early() {
            return Err(anyhow!("Authorization Token used too early"));
        }

        let chain = ProofChain::from_ucan(
            ucan,
            Some(now_time),
            &mut DidParser::new(SLINGER_SUPPORTED_KEYS),
            &self.store,
        )
        .await?;

        let root_pub_key = PublicKey::from_str(&self.root_endpoint_id.to_string())?;
        let expected_root_did = IrohKeyMaterial::public_key_to_did(&root_pub_key);

        if get_root_issuer(&chain) != expected_root_did {
            return Err(anyhow!("Unauthorized Root: {}", chain.ucan().issuer()));
        }

        Ok(chain.reduce_capabilities(&SlingerSemantics))
    }

    pub fn now_time() -> u64 {
        let now = SystemTime::now();
        let since_the_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

        since_the_epoch.as_secs()
    }
}

pub const SLINGER_SUPPORTED_KEYS: &ucan::crypto::did::KeyConstructorSlice = &[(
    ucan_key_support::ed25519::ED25519_MAGIC_BYTES,
    ucan_key_support::ed25519::bytes_to_ed25519_key,
)];

// TODO: change from recursive to iterator
pub fn get_root_issuer(chain: &ucan::chain::ProofChain) -> String {
    match chain.proofs().first() {
        Some(parent_chain) => get_root_issuer(parent_chain),
        None => chain.ucan().issuer().to_string(),
    }
}

//
// UCAN implementations for Ability, Scope, and CapabilitySemantics
//

pub type SlingerCapabilityView = ucan::capability::CapabilityView<SlingerScope, SlingerAbility>;

#[derive(Debug, Clone)]
pub enum NodeCapability {
    DeploymentNotify { namespace: String },
    ReadBlob { hash: String },
    ReplicateBlob { hash: String },
    JoinTopic { topic_id: String },
    EmitTopic { topic_id: String },
}

impl NodeCapability {
    pub fn to_ucan_capability_view(&self) -> SlingerCapabilityView {
        let (resource_url, ability) = match self {
            NodeCapability::DeploymentNotify { namespace } => (
                format!("slinger://deployments/{}", namespace),
                SlingerAbility::AnnounceDeployment,
            ),
            NodeCapability::ReadBlob { hash } => (
                format!("slinger://blobs/hash-{}", hash),
                SlingerAbility::ReadBlob,
            ),
            NodeCapability::ReplicateBlob { hash } => (
                format!("slinger://blobs/hash-{}", hash),
                SlingerAbility::ReplicateBlob,
            ),
            NodeCapability::JoinTopic { topic_id } => (
                format!("slinger://gossip-topic/{}", topic_id),
                SlingerAbility::JoinGossipTopic,
            ),
            NodeCapability::EmitTopic { topic_id } => (
                format!("slinger://gossip-topic/{}", topic_id),
                SlingerAbility::EmitGoissipTopic,
            ),
        };

        let resource_uri = ResourceUri::Scoped(
            SlingerScope::try_from(url::Url::parse(&resource_url).unwrap()).unwrap(),
        );
        let resource = Resource::Resource { kind: resource_uri };

        SlingerCapabilityView {
            ability,
            resource,
            caveat: json!({}),
        }
    }
}

pub struct SlingerSemantics;

impl ucan::capability::CapabilitySemantics<SlingerScope, SlingerAbility> for SlingerSemantics {}

// NOTE: derive traits required by ucan::capability::Ability
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlingerAbility {
    // Deployment permissions
    AnnounceDeployment,

    // Blob (artifact) permisions
    ReadBlob,
    ReplicateBlob,

    // Gossip topic permisions
    JoinGossipTopic,
    EmitGoissipTopic,
}

impl ucan::capability::Ability for SlingerAbility {}

// NOTE: derive traits required by ucan::capability::Scope
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlingerScope(url::Url);

impl ucan::capability::Scope for SlingerScope {
    fn contains(&self, other: &Self) -> bool {
        let self_str = self.0.as_str();
        let other_str = other.0.as_str();

        if self_str.ends_with('*') {
            // Prefix matching for wildcards
            let prefix = &self_str[..self_str.len() - 1];
            other_str.starts_with(prefix)
        } else {
            // Exact matching
            self_str == other_str
        }
    }
}

// NOTE: required by trait ucan::capability::Ability
impl fmt::Display for SlingerAbility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AnnounceDeployment => "slinger/deployments/notify",
            Self::ReadBlob => "slinger/blobs/read",
            Self::ReplicateBlob => "slinger/blobs/replicate",
            Self::JoinGossipTopic => "slinger/gossip/join",
            Self::EmitGoissipTopic => "slinger/gossip/emit",
        };
        write!(f, "{}", s)
    }
}

// NOTE: required by trait ucan::capability::Ability
impl TryFrom<String> for SlingerAbility {
    type Error = anyhow::Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "slinger/deployments/notify" => Ok(Self::AnnounceDeployment),
            "slinger/blobs/read" => Ok(Self::ReadBlob),
            "slinger/blobs/replicate" => Ok(Self::ReplicateBlob),
            "slinger/gossip/join" => Ok(Self::JoinGossipTopic),
            "slinger/gossip/emit" => Ok(Self::EmitGoissipTopic),
            _ => Err(anyhow::anyhow!("Unknown ability: {}", s)),
        }
    }
}

// NOTE: required by trait ucan::capability::Scope
impl fmt::Display for SlingerScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// NOTE: required by trait ucan::capability::Scope
impl TryFrom<url::Url> for SlingerScope {
    type Error = anyhow::Error;
    fn try_from(u: url::Url) -> Result<Self, Self::Error> {
        if u.scheme() != "slinger" {
            return Err(anyhow::anyhow!("Invalid scheme: must be slinger://"));
        }
        Ok(SlingerScope(u))
    }
}
