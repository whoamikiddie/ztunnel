/**
 * FFI Exports and ChaCha20-Poly1305 AEAD
 */

#include "zcrypto.hpp"
#include <cstring>
#include <cstdlib>

extern void chacha20_encrypt(uint8_t*, const uint8_t*, size_t, const uint8_t[32], const uint8_t[12], uint32_t);
extern void poly1305_auth(uint8_t[16], const uint8_t*, size_t, const uint8_t[32]);

extern "C" int zcrypto_memcmp(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* pb = static_cast<const volatile uint8_t*>(b);
    int result = 0;
    for (size_t i = 0; i < len; i++) result |= pa[i] ^ pb[i];
    return result;
}

extern "C" void zcrypto_memzero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

extern "C" void zcrypto_chacha20_poly1305_encrypt(
    uint8_t* ciphertext, uint8_t tag[16],
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len
) {
    uint8_t poly_key[64] = {0}, zeros[64] = {0};
    chacha20_encrypt(poly_key, zeros, 64, key, nonce, 0);
    chacha20_encrypt(ciphertext, plaintext, plaintext_len, key, nonce, 1);
    
    size_t msg_len = ((aad_len + 15) & ~15) + ((plaintext_len + 15) & ~15) + 16;
    uint8_t* msg = static_cast<uint8_t*>(calloc(1, msg_len));
    size_t off = 0;
    if (aad && aad_len) { std::memcpy(msg, aad, aad_len); off = (aad_len + 15) & ~15; }
    std::memcpy(msg + off, ciphertext, plaintext_len);
    off = msg_len - 16;
    for (int i = 0; i < 8; i++) { msg[off+i] = aad_len >> (i*8); msg[off+8+i] = plaintext_len >> (i*8); }
    
    poly1305_auth(tag, msg, msg_len, poly_key);
    zcrypto_memzero(poly_key, 64); free(msg);
}

extern "C" int zcrypto_chacha20_poly1305_decrypt(
    uint8_t* plaintext, const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len
) {
    uint8_t poly_key[64] = {0}, zeros[64] = {0};
    chacha20_encrypt(poly_key, zeros, 64, key, nonce, 0);
    
    size_t msg_len = ((aad_len + 15) & ~15) + ((ciphertext_len + 15) & ~15) + 16;
    uint8_t* msg = static_cast<uint8_t*>(calloc(1, msg_len));
    size_t off = 0;
    if (aad && aad_len) { std::memcpy(msg, aad, aad_len); off = (aad_len + 15) & ~15; }
    std::memcpy(msg + off, ciphertext, ciphertext_len);
    off = msg_len - 16;
    for (int i = 0; i < 8; i++) { msg[off+i] = aad_len >> (i*8); msg[off+8+i] = ciphertext_len >> (i*8); }
    
    uint8_t computed[16];
    poly1305_auth(computed, msg, msg_len, poly_key);
    zcrypto_memzero(poly_key, 64); free(msg);
    
    if (zcrypto_memcmp(tag, computed, 16) != 0) return -1;
    chacha20_encrypt(plaintext, ciphertext, ciphertext_len, key, nonce, 1);
    return 0;
}
