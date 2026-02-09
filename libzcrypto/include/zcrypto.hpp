#pragma once
/**
 * libzcrypto - ZTunnel Cryptographic Library
 * 
 * Provides high-performance, timing-attack resistant cryptographic primitives:
 * - X25519: ECDH key exchange
 * - ChaCha20-Poly1305: AEAD encryption
 * - HKDF-SHA256: Key derivation
 */

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// X25519 Key Exchange
// ============================================================================

/**
 * Generate a new X25519 keypair.
 * 
 * @param public_key  Output: 32-byte public key
 * @param private_key Output: 32-byte private key
 */
void zcrypto_x25519_keygen(uint8_t public_key[32], uint8_t private_key[32]);

/**
 * Compute shared secret from private key and peer's public key.
 * 
 * @param shared_secret Output: 32-byte shared secret
 * @param private_key   Your 32-byte private key
 * @param peer_public   Peer's 32-byte public key
 */
void zcrypto_x25519_shared_secret(
    uint8_t shared_secret[32],
    const uint8_t private_key[32],
    const uint8_t peer_public[32]
);

// ============================================================================
// ChaCha20-Poly1305 AEAD
// ============================================================================

/**
 * Encrypt data with ChaCha20-Poly1305.
 * 
 * @param ciphertext    Output: encrypted data (same length as plaintext)
 * @param tag           Output: 16-byte authentication tag
 * @param plaintext     Input data to encrypt
 * @param plaintext_len Length of plaintext in bytes
 * @param key           32-byte encryption key
 * @param nonce         12-byte nonce (MUST be unique per message)
 * @param aad           Additional authenticated data (can be NULL)
 * @param aad_len       Length of AAD in bytes
 */
void zcrypto_chacha20_poly1305_encrypt(
    uint8_t* ciphertext,
    uint8_t tag[16],
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len
);

/**
 * Decrypt data with ChaCha20-Poly1305.
 * 
 * @param plaintext      Output: decrypted data (same length as ciphertext)
 * @param ciphertext     Encrypted data
 * @param ciphertext_len Length of ciphertext in bytes
 * @param tag            16-byte authentication tag
 * @param key            32-byte encryption key
 * @param nonce          12-byte nonce (same as used for encryption)
 * @param aad            Additional authenticated data (can be NULL)
 * @param aad_len        Length of AAD in bytes
 * @return 0 on success, -1 if authentication fails
 */
int zcrypto_chacha20_poly1305_decrypt(
    uint8_t* plaintext,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t tag[16],
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len
);

// ============================================================================
// HKDF-SHA256 Key Derivation
// ============================================================================

/**
 * Derive key material using HKDF-SHA256.
 * 
 * @param out       Output: derived key material
 * @param out_len   Length of output in bytes (max 255 * 32)
 * @param ikm       Input keying material
 * @param ikm_len   Length of IKM in bytes
 * @param salt      Optional salt (can be NULL)
 * @param salt_len  Length of salt in bytes
 * @param info      Optional context/application-specific info
 * @param info_len  Length of info in bytes
 */
void zcrypto_hkdf_sha256(
    uint8_t* out,
    size_t out_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len
);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Secure memory comparison (constant-time).
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return 0 if equal, non-zero otherwise
 */
int zcrypto_memcmp(const void* a, const void* b, size_t len);

/**
 * Secure memory zeroing.
 * 
 * @param ptr Pointer to memory
 * @param len Length to zero
 */
void zcrypto_memzero(void* ptr, size_t len);

#ifdef __cplusplus
}

// C++ namespace wrapper
namespace zcrypto {

struct X25519Keypair {
    uint8_t public_key[32];
    uint8_t private_key[32];
    
    static X25519Keypair generate() {
        X25519Keypair kp;
        zcrypto_x25519_keygen(kp.public_key, kp.private_key);
        return kp;
    }
    
    void shared_secret(uint8_t out[32], const uint8_t peer_public[32]) const {
        zcrypto_x25519_shared_secret(out, private_key, peer_public);
    }
};

} // namespace zcrypto

#endif
