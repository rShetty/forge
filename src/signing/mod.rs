use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{ForgeError, Result};

pub struct SigningEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

impl SigningEngine {
    pub fn generate_keypair() -> KeyPair {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        KeyPair {
            public_key: base64::engine::general_purpose::STANDARD.encode(verifying_key.to_bytes()),
            private_key: base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes()),
        }
    }

    pub fn hash_file(path: &str) -> Result<String> {
        let content = std::fs::read(path)
            .map_err(|e| ForgeError::Config(format!("failed to read file: {}", e)))?;
        Self::hash_bytes(&content)
    }

    pub fn hash_bytes(content: &[u8]) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn sign(private_key_b64: &str, message: &[u8]) -> Result<String> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(private_key_b64)
            .map_err(|e| ForgeError::SignatureInvalid(format!("key decode: {}", e)))?;
        let signing_key = SigningKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ForgeError::SignatureInvalid("invalid key length".to_string()))?,
        );
        let signature: Signature = signing_key.sign(message);
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }

    pub fn verify(public_key_b64: &str, message: &[u8], signature_b64: &str) -> Result<bool> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(public_key_b64)
            .map_err(|e| ForgeError::SignatureInvalid(format!("key decode: {}", e)))?;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| ForgeError::SignatureInvalid(format!("sig decode: {}", e)))?;

        let verifying_key = VerifyingKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ForgeError::SignatureInvalid("invalid key length".to_string()))?,
        )
        .map_err(|e: ed25519_dalek::SignatureError| ForgeError::SignatureInvalid(e.to_string()))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| ForgeError::SignatureInvalid("invalid sig length".to_string()))?,
        );

        match verifying_key.verify(message, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let kp = SigningEngine::generate_keypair();
        let message = b"hello agent";
        let signature = SigningEngine::sign(&kp.private_key, message).unwrap();
        let valid = SigningEngine::verify(&kp.public_key, message, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message() {
        let kp = SigningEngine::generate_keypair();
        let signature = SigningEngine::sign(&kp.private_key, b"message 1").unwrap();
        let valid = SigningEngine::verify(&kp.public_key, b"message 2", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_key() {
        let kp1 = SigningEngine::generate_keypair();
        let kp2 = SigningEngine::generate_keypair();
        let signature = SigningEngine::sign(&kp1.private_key, b"message").unwrap();
        let valid = SigningEngine::verify(&kp2.public_key, b"message", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_hash_bytes() {
        let h1 = SigningEngine::hash_bytes(b"test").unwrap();
        let h2 = SigningEngine::hash_bytes(b"test").unwrap();
        let h3 = SigningEngine::hash_bytes(b"different").unwrap();
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 64);
    }
}
