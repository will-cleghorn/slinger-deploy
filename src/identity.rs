use crate::common::types::{Deployment, SignedDeployment};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use iroh::{PublicKey, SecretKey, Signature};
use ucan::crypto::KeyMaterial;

pub struct IrohKeyMaterial {
    pub secret_key: SecretKey,
}

impl IrohKeyMaterial {
    pub fn new(secret_key: SecretKey) -> Self {
        Self { secret_key }
    }

    /// Generates the did:key:z... string for an Ed25519 public key.
    pub fn public_key_to_did(public_key: &PublicKey) -> String {
        // Multicodec prefix for Ed25519 is 0xed 0x01
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(public_key.as_bytes());

        let encoded = bs58::encode(bytes).into_string();

        format!("did:key:z{}", encoded)
    }
}

#[async_trait]
impl KeyMaterial for IrohKeyMaterial {
    /// Returns the decentralized identifier (DID) for this key
    async fn get_did(&self) -> Result<String> {
        let did_string = Self::public_key_to_did(&self.secret_key.public());
        Ok(did_string)
    }

    /// Signs the provided data using Iroh's Ed25519 secret key
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.secret_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Returns the JWT algorithm identifier for Ed25519
    fn get_jwt_algorithm_name(&self) -> String {
        "EdDSA".to_string()
    }

    async fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::from_bytes(
            signature
                .try_into()
                .map_err(|e| anyhow!("Invalid byte payload for signature: {}", e))?,
        );

        let public_key = self.secret_key.public();

        public_key
            .verify(payload, &sig)
            .map_err(|e| anyhow!("Signature mismatch: {}", e))?;

        Ok(())
    }
}

pub fn sign_deployment(secret_key: &SecretKey, deployment: Deployment) -> Result<SignedDeployment> {
    let data = postcard::to_stdvec(&deployment)?;
    let signature = secret_key.sign(&data);

    Ok(SignedDeployment {
        deployment,
        signature: signature.to_bytes().to_vec(),
    })
}

pub fn verify_deployment(public_key: &PublicKey, signed: &SignedDeployment) -> Result<()> {
    let data = postcard::to_stdvec(&signed.deployment)?;

    let sig = Signature::from_bytes(
        &signed
            .signature
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Invalid signature length"))?,
    );

    public_key
        .verify(&data, &sig)
        .map_err(|e| anyhow!("Signature verification failed: {}", e))
}

pub struct StringKeyPair {
    pub public: String,
    pub private: String,
}

impl StringKeyPair {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let key = SecretKey::generate(&mut rng);
        let public = key.clone().public();

        StringKeyPair {
            public: hex::encode(key.to_bytes()),
            private: hex::encode(public.as_bytes()),
        }
    }
}
