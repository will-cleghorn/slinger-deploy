use std::path::PathBuf;

use iroh::Endpoint;
use iroh_blobs::{api::Store, ticket::BlobTicket};

use crate::common::types::SignedDeployment;

pub struct Artifact {
    path: PathBuf,
    endpoint: Endpoint,
    store: Store,
    version: String,
    created_timestamp: u64,
}

impl Artifact {
    async fn host(&self) -> anyhow::Result<BlobTicket> {
        todo!()
    }

    pub async fn deploy(&self) -> anyhow::Result<SignedDeployment> {
        todo!()
    }
}
