/**
 * HKDF-SHA256 Key Derivation Function
 * 
 * RFC 5869 implementation.
 */

#include "zcrypto.hpp"
#include <cstring>

namespace {

// SHA-256 constants
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

struct SHA256State {
    uint32_t h[8];
    uint8_t buffer[64];
    size_t buflen;
    uint64_t total;
};

void sha256_init(SHA256State& st) {
    st.h[0] = 0x6a09e667; st.h[1] = 0xbb67ae85;
    st.h[2] = 0x3c6ef372; st.h[3] = 0xa54ff53a;
    st.h[4] = 0x510e527f; st.h[5] = 0x9b05688c;
    st.h[6] = 0x1f83d9ab; st.h[7] = 0x5be0cd19;
    st.buflen = 0;
    st.total = 0;
}

void sha256_compress(SHA256State& st, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4 + 1] << 16) |
               ((uint32_t)block[i*4 + 2] << 8) | (uint32_t)block[i*4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }
    
    a = st.h[0]; b = st.h[1]; c = st.h[2]; d = st.h[3];
    e = st.h[4]; f = st.h[5]; g = st.h[6]; h = st.h[7];
    
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    st.h[0] += a; st.h[1] += b; st.h[2] += c; st.h[3] += d;
    st.h[4] += e; st.h[5] += f; st.h[6] += g; st.h[7] += h;
}

void sha256_update(SHA256State& st, const uint8_t* data, size_t len) {
    st.total += len;
    
    if (st.buflen > 0) {
        size_t need = 64 - st.buflen;
        if (len < need) {
            std::memcpy(st.buffer + st.buflen, data, len);
            st.buflen += len;
            return;
        }
        std::memcpy(st.buffer + st.buflen, data, need);
        sha256_compress(st, st.buffer);
        data += need;
        len -= need;
        st.buflen = 0;
    }
    
    while (len >= 64) {
        sha256_compress(st, data);
        data += 64;
        len -= 64;
    }
    
    if (len > 0) {
        std::memcpy(st.buffer, data, len);
        st.buflen = len;
    }
}

void sha256_final(SHA256State& st, uint8_t hash[32]) {
    uint8_t pad[64] = {0x80};
    size_t padlen = (st.buflen < 56) ? (56 - st.buflen) : (120 - st.buflen);
    
    uint64_t bits = st.total * 8;
    uint8_t lenblock[8];
    for (int i = 0; i < 8; i++) {
        lenblock[i] = (uint8_t)(bits >> (56 - i * 8));
    }
    
    sha256_update(st, pad, padlen);
    sha256_update(st, lenblock, 8);
    
    for (int i = 0; i < 8; i++) {
        hash[i*4]     = (uint8_t)(st.h[i] >> 24);
        hash[i*4 + 1] = (uint8_t)(st.h[i] >> 16);
        hash[i*4 + 2] = (uint8_t)(st.h[i] >> 8);
        hash[i*4 + 3] = (uint8_t)(st.h[i]);
    }
}

void sha256(uint8_t hash[32], const uint8_t* data, size_t len) {
    SHA256State st;
    sha256_init(st);
    sha256_update(st, data, len);
    sha256_final(st, hash);
}

// HMAC-SHA256
void hmac_sha256(
    uint8_t out[32],
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len
) {
    uint8_t key_block[64] = {0};
    uint8_t ipad[64], opad[64];
    
    // Key processing
    if (key_len > 64) {
        sha256(key_block, key, key_len);
    } else {
        std::memcpy(key_block, key, key_len);
    }
    
    // Create pads
    for (int i = 0; i < 64; i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    
    // Inner hash
    SHA256State st;
    sha256_init(st);
    sha256_update(st, ipad, 64);
    sha256_update(st, data, data_len);
    uint8_t inner[32];
    sha256_final(st, inner);
    
    // Outer hash
    sha256_init(st);
    sha256_update(st, opad, 64);
    sha256_update(st, inner, 32);
    sha256_final(st, out);
    
    zcrypto_memzero(key_block, 64);
    zcrypto_memzero(ipad, 64);
    zcrypto_memzero(opad, 64);
    zcrypto_memzero(inner, 32);
}

} // anonymous namespace

// HKDF-SHA256 per RFC 5869
extern "C" void zcrypto_hkdf_sha256(
    uint8_t* out,
    size_t out_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len
) {
    // HKDF-Extract
    uint8_t prk[32];
    if (salt == nullptr || salt_len == 0) {
        uint8_t zero_salt[32] = {0};
        hmac_sha256(prk, zero_salt, 32, ikm, ikm_len);
    } else {
        hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
    }
    
    // HKDF-Expand
    uint8_t t[32] = {0};
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t offset = 0;
    
    while (offset < out_len) {
        // T(n) = HMAC(PRK, T(n-1) || info || counter)
        SHA256State st;
        sha256_init(st);
        
        // Setup HMAC
        uint8_t key_block[64] = {0};
        std::memcpy(key_block, prk, 32);
        uint8_t ipad[64], opad[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5c;
        }
        
        // Inner hash
        sha256_init(st);
        sha256_update(st, ipad, 64);
        if (t_len > 0) sha256_update(st, t, t_len);
        if (info_len > 0) sha256_update(st, info, info_len);
        sha256_update(st, &counter, 1);
        uint8_t inner[32];
        sha256_final(st, inner);
        
        // Outer hash
        sha256_init(st);
        sha256_update(st, opad, 64);
        sha256_update(st, inner, 32);
        sha256_final(st, t);
        t_len = 32;
        
        size_t copy_len = (out_len - offset < 32) ? (out_len - offset) : 32;
        std::memcpy(out + offset, t, copy_len);
        offset += copy_len;
        counter++;
    }
    
    zcrypto_memzero(prk, 32);
    zcrypto_memzero(t, 32);
}
