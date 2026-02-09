/**
 * libzcrypto Test Suite
 */

#include "../include/zcrypto.hpp"
#include <cstdio>
#include <cstring>

#define TEST(name) static bool test_##name()
#define RUN(name) do { printf("  %-40s", #name); if (test_##name()) { printf("[PASS]\n"); passed++; } else { printf("[FAIL]\n"); failed++; } } while(0)

TEST(memzero) {
    uint8_t buf[32] = {1,2,3,4,5,6,7,8};
    zcrypto_memzero(buf, 32);
    for (int i = 0; i < 32; i++) if (buf[i] != 0) return false;
    return true;
}

TEST(memcmp_equal) {
    uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    return zcrypto_memcmp(a, b, 16) == 0;
}

TEST(memcmp_differ) {
    uint8_t a[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t b[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,17};
    return zcrypto_memcmp(a, b, 16) != 0;
}

TEST(x25519_keygen) {
    uint8_t pub[32], priv[32];
    zcrypto_x25519_keygen(pub, priv);
    // Check keys are not all zeros
    bool pub_ok = false, priv_ok = false;
    for (int i = 0; i < 32; i++) { if (pub[i]) pub_ok = true; if (priv[i]) priv_ok = true; }
    return pub_ok && priv_ok;
}

TEST(x25519_shared_secret) {
    uint8_t pub1[32], priv1[32], pub2[32], priv2[32];
    uint8_t shared1[32], shared2[32];
    
    zcrypto_x25519_keygen(pub1, priv1);
    zcrypto_x25519_keygen(pub2, priv2);
    
    zcrypto_x25519_shared_secret(shared1, priv1, pub2);
    zcrypto_x25519_shared_secret(shared2, priv2, pub1);
    
    return zcrypto_memcmp(shared1, shared2, 32) == 0;
}

TEST(hkdf_basic) {
    uint8_t ikm[32] = {0x0b};
    uint8_t out[32];
    zcrypto_hkdf_sha256(out, 32, ikm, 1, nullptr, 0, nullptr, 0);
    
    bool not_zero = false;
    for (int i = 0; i < 32; i++) if (out[i]) not_zero = true;
    return not_zero;
}

TEST(chacha20_poly1305_roundtrip) {
    uint8_t key[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    uint8_t nonce[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t plaintext[] = "Hello, ZTunnel!";
    size_t len = sizeof(plaintext) - 1;
    
    uint8_t ciphertext[64], decrypted[64], tag[16];
    
    zcrypto_chacha20_poly1305_encrypt(ciphertext, tag, plaintext, len, key, nonce, nullptr, 0);
    int result = zcrypto_chacha20_poly1305_decrypt(decrypted, ciphertext, len, tag, key, nonce, nullptr, 0);
    
    if (result != 0) return false;
    return memcmp(plaintext, decrypted, len) == 0;
}

int main() {
    int passed = 0, failed = 0;
    
    printf("\n=== libzcrypto Test Suite ===\n\n");
    
    RUN(memzero);
    RUN(memcmp_equal);
    RUN(memcmp_differ);
    RUN(x25519_keygen);
    RUN(x25519_shared_secret);
    RUN(hkdf_basic);
    RUN(chacha20_poly1305_roundtrip);
    
    printf("\n----------------------------\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    
    return failed > 0 ? 1 : 0;
}
