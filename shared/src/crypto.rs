//! FFI bindings to libzcrypto (C++ + ASM).
//!
//! This module provides safe Rust wrappers around the C FFI.

use crate::{Error, Result};

/// X25519 keypair
#[derive(Clone)]
pub struct X25519Keypair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

/// Session state for encrypted communication
pub struct Session {
    pub session_key: [u8; 32],
    pub nonce_counter: u64,
}

// FFI declarations - will link to libzcrypto
#[cfg(feature = "libzcrypto")]
mod ffi {
    extern "C" {
        pub fn zcrypto_x25519_keygen(public_key: *mut u8, private_key: *mut u8);
        pub fn zcrypto_x25519_shared_secret(
            out: *mut u8,
            private_key: *const u8,
            peer_public: *const u8,
        );
        pub fn zcrypto_chacha20_poly1305_encrypt(
            ciphertext: *mut u8,
            tag: *mut u8,
            plaintext: *const u8,
            plaintext_len: usize,
            key: *const u8,
            nonce: *const u8,
            aad: *const u8,
            aad_len: usize,
        );
        pub fn zcrypto_chacha20_poly1305_decrypt(
            plaintext: *mut u8,
            ciphertext: *const u8,
            ciphertext_len: usize,
            tag: *const u8,
            key: *const u8,
            nonce: *const u8,
            aad: *const u8,
            aad_len: usize,
        ) -> i32;
        pub fn zcrypto_hkdf_sha256(
            out: *mut u8,
            out_len: usize,
            ikm: *const u8,
            ikm_len: usize,
            salt: *const u8,
            salt_len: usize,
            info: *const u8,
            info_len: usize,
        );
    }
}

impl X25519Keypair {
    /// Generate a new X25519 keypair
    #[cfg(feature = "libzcrypto")]
    pub fn generate() -> Self {
        let mut keypair = X25519Keypair {
            public_key: [0u8; 32],
            private_key: [0u8; 32],
        };
        unsafe {
            ffi::zcrypto_x25519_keygen(
                keypair.public_key.as_mut_ptr(),
                keypair.private_key.as_mut_ptr(),
            );
        }
        keypair
    }

    /// Placeholder for when libzcrypto is not linked
    #[cfg(not(feature = "libzcrypto"))]
    pub fn generate() -> Self {
        // TODO: Use libzcrypto when available
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        
        let mut private_key = [0u8; 32];
        let mut public_key = [0u8; 32];
        
        // Simple placeholder - NOT cryptographically secure
        for i in 0..32 {
            private_key[i] = ((seed >> (i % 8)) ^ (i as u64 * 17)) as u8;
            public_key[i] = private_key[i] ^ 0x55;
        }
        
        X25519Keypair { public_key, private_key }
    }

    /// Compute shared secret with peer's public key
    #[cfg(feature = "libzcrypto")]
    pub fn shared_secret(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let mut shared = [0u8; 32];
        unsafe {
            ffi::zcrypto_x25519_shared_secret(
                shared.as_mut_ptr(),
                self.private_key.as_ptr(),
                peer_public.as_ptr(),
            );
        }
        shared
    }

    #[cfg(not(feature = "libzcrypto"))]
    pub fn shared_secret(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        // Placeholder XOR - NOT cryptographically secure
        let mut shared = [0u8; 32];
        for i in 0..32 {
            shared[i] = self.private_key[i] ^ peer_public[i];
        }
        shared
    }
}

impl Session {
    /// Create a new session from shared secret
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let mut session_key = [0u8; 32];
        
        #[cfg(feature = "libzcrypto")]
        {
            let info = b"ztunnel-session-v1";
            unsafe {
                ffi::zcrypto_hkdf_sha256(
                    session_key.as_mut_ptr(),
                    32,
                    shared_secret.as_ptr(),
                    32,
                    std::ptr::null(),
                    0,
                    info.as_ptr(),
                    info.len(),
                );
            }
        }
        
        #[cfg(not(feature = "libzcrypto"))]
        {
            // Placeholder - just copy shared secret
            session_key.copy_from_slice(shared_secret);
        }
        
        Session {
            session_key,
            nonce_counter: 0,
        }
    }

    /// Get next nonce (12 bytes)
    pub fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter += 1;
        nonce
    }

    /// Encrypt data
    #[cfg(feature = "libzcrypto")]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12], [u8; 16])> {
        let nonce = self.next_nonce();
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];

        unsafe {
            ffi::zcrypto_chacha20_poly1305_encrypt(
                ciphertext.as_mut_ptr(),
                tag.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                self.session_key.as_ptr(),
                nonce.as_ptr(),
                std::ptr::null(),
                0,
            );
        }

        Ok((ciphertext, nonce, tag))
    }

    #[cfg(not(feature = "libzcrypto"))]
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12], [u8; 16])> {
        let nonce = self.next_nonce();
        // Placeholder XOR encryption - NOT secure
        let ciphertext: Vec<u8> = plaintext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.session_key[i % 32] ^ nonce[i % 12])
            .collect();
        let tag = [0u8; 16]; // Placeholder
        Ok((ciphertext, nonce, tag))
    }

    /// Decrypt data  
    #[cfg(feature = "libzcrypto")]
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12], tag: &[u8; 16]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];

        let result = unsafe {
            ffi::zcrypto_chacha20_poly1305_decrypt(
                plaintext.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                tag.as_ptr(),
                self.session_key.as_ptr(),
                nonce.as_ptr(),
                std::ptr::null(),
                0,
            )
        };

        if result != 0 {
            return Err(Error::Crypto("Decryption failed".into()));
        }

        Ok(plaintext)
    }

    #[cfg(not(feature = "libzcrypto"))]
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12], _tag: &[u8; 16]) -> Result<Vec<u8>> {
        // Placeholder XOR decryption - NOT secure
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ self.session_key[i % 32] ^ nonce[i % 12])
            .collect();
        Ok(plaintext)
    }
}
