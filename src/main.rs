// #![allow(dead_code)] // FIXME remove
mod authentication;
mod common;
mod consumer;
mod identity;
mod producer;
mod protocol;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use iroh::SecretKey;
use ucan::builder::UcanBuilder;

use crate::{
    authentication::ucans::NodeCapability,
    consumer::Consumer,
    identity::{IrohKeyMaterial, StringKeyPair},
    producer::Producer,
    protocol::gossip::derive_topic_id,
};

#[derive(Parser)]
#[command(name = "slinger")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Produce {
        #[arg(short, long)]
        path: PathBuf,

        #[arg(long)]
        private_key: String,
    },
    Consume {
        #[arg(short, long)]
        ticket: String,
        #[arg(long)]
        tier: u8,
    },
    KeyGen,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // let stdout_subscriber = tracing_subscriber::fmt::init();
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Produce { path, private_key } => {
            let key: SecretKey = private_key.as_str().parse()?;
            run_producer(path, key).await?;
        }
        Commands::Consume { ticket, tier } => {
            run_consumer(ticket, *tier).await?;
        }
        Commands::KeyGen => {
            let kp = StringKeyPair::new();
            println!("Private key {}", kp.private);
            println!("Public key {}", kp.public);
        }
    }

    Ok(())
}

async fn run_producer(path: &PathBuf, pk: SecretKey) -> anyhow::Result<()> {
    let encoded_test_ucan =
        producer_test_ucan(pk.clone(), pk.clone(), "slinger-test-secret", "prod-1").await?;
    let _producer = Producer::new(
        pk,
        "secret-1",
        "deployment-1",
        path.to_path_buf(),
        encoded_test_ucan,
    )
    .await?;

    loop {}
}

async fn run_consumer(ticket: &str, tier: u8) -> anyhow::Result<()> {
    let _consumer = Consumer::new("secret-1", "deployment-1", ticket, tier).await?;
    loop {}
}

async fn producer_test_ucan(
    root_private_key: SecretKey,
    producer_private_key: SecretKey,
    cluster_secret: &str,
    namespace: &str,
) -> anyhow::Result<String> {
    let key_material = IrohKeyMaterial::new(root_private_key.clone());
    let pub_did = IrohKeyMaterial::public_key_to_did(&producer_private_key.public());

    Ok(UcanBuilder::default()
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
        .encode()?)
}
