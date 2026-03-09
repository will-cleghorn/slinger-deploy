use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignalMessage {
    pub encoded_ucan: String,
    pub signal: Signal,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum Signal {
    Deploy(SignedDeployment),
    Heartbeat(NodeStatus),
    Revoke { node_id: String, reason: String },
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Deployment {
    pub version: String,
    pub ticket: String,
    pub created_date: u64,
    pub deployer_tier: Option<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NodeStatus {
    pub node_id: String,
    pub is_replicating: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SignedDeployment {
    pub deployment: Deployment,
    pub signature: Vec<u8>,
}
