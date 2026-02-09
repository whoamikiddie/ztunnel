/**
 * X25519 Key Exchange Implementation
 * 
 * Elliptic Curve Diffie-Hellman on Curve25519.
 */

#include "zcrypto.hpp"
#include <cstring>

namespace {

// Field element (256-bit)
using fe25519 = int64_t[10];

// Constants
constexpr int64_t FIELD_BASE = 1 << 26;

// Field arithmetic
void fe_frombytes(fe25519 h, const uint8_t s[32]) {
    int64_t h0 = (int64_t)(s[0]) | ((int64_t)s[1] << 8) | ((int64_t)s[2] << 16) | ((int64_t)(s[3] & 63) << 24);
    int64_t h1 = ((int64_t)(s[3] >> 6)) | ((int64_t)s[4] << 2) | ((int64_t)s[5] << 10) | ((int64_t)s[6] << 18) | ((int64_t)(s[7] & 1) << 26);
    int64_t h2 = ((int64_t)(s[7] >> 1)) | ((int64_t)s[8] << 7) | ((int64_t)s[9] << 15) | ((int64_t)(s[10] & 7) << 23);
    int64_t h3 = ((int64_t)(s[10] >> 3)) | ((int64_t)s[11] << 5) | ((int64_t)s[12] << 13) | ((int64_t)(s[13] & 31) << 21);
    int64_t h4 = ((int64_t)(s[13] >> 5)) | ((int64_t)s[14] << 3) | ((int64_t)s[15] << 11) | ((int64_t)(s[16] & 127) << 19);
    int64_t h5 = ((int64_t)(s[16] >> 7)) | ((int64_t)s[17] << 1) | ((int64_t)s[18] << 9) | ((int64_t)s[19] << 17) | ((int64_t)(s[20] & 3) << 25);
    int64_t h6 = ((int64_t)(s[20] >> 2)) | ((int64_t)s[21] << 6) | ((int64_t)s[22] << 14) | ((int64_t)(s[23] & 15) << 22);
    int64_t h7 = ((int64_t)(s[23] >> 4)) | ((int64_t)s[24] << 4) | ((int64_t)s[25] << 12) | ((int64_t)(s[26] & 63) << 20);
    int64_t h8 = ((int64_t)(s[26] >> 6)) | ((int64_t)s[27] << 2) | ((int64_t)s[28] << 10) | ((int64_t)s[29] << 18);
    int64_t h9 = ((int64_t)s[30]) | ((int64_t)s[31] << 8);
    
    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3; h[4] = h4;
    h[5] = h5; h[6] = h6; h[7] = h7; h[8] = h8; h[9] = h9;
}

void fe_tobytes(uint8_t s[32], const fe25519 h) {
    int64_t t[10];
    std::memcpy(t, h, sizeof(t));
    
    // Reduce modulo 2^255 - 19
    int64_t q = (19 * t[9] + (1 << 24)) >> 25;
    for (int i = 0; i < 5; i++) {
        q = (t[2*i] + q) >> 26;
        q = (t[2*i + 1] + q) >> 25;
    }
    t[0] += 19 * q;
    
    int64_t carry = 0;
    for (int i = 0; i < 9; i++) {
        t[i] += carry;
        carry = t[i] >> ((i & 1) ? 25 : 26);
        t[i] &= ((i & 1) ? 0x1ffffff : 0x3ffffff);
    }
    t[9] += carry;
    
    // Output
    s[0] = (uint8_t)(t[0]);
    s[1] = (uint8_t)(t[0] >> 8);
    s[2] = (uint8_t)(t[0] >> 16);
    s[3] = (uint8_t)((t[0] >> 24) | (t[1] << 2));
    s[4] = (uint8_t)(t[1] >> 6);
    s[5] = (uint8_t)(t[1] >> 14);
    s[6] = (uint8_t)((t[1] >> 22) | (t[2] << 3));
    s[7] = (uint8_t)(t[2] >> 5);
    s[8] = (uint8_t)(t[2] >> 13);
    s[9] = (uint8_t)((t[2] >> 21) | (t[3] << 5));
    s[10] = (uint8_t)(t[3] >> 3);
    s[11] = (uint8_t)(t[3] >> 11);
    s[12] = (uint8_t)((t[3] >> 19) | (t[4] << 6));
    s[13] = (uint8_t)(t[4] >> 2);
    s[14] = (uint8_t)(t[4] >> 10);
    s[15] = (uint8_t)(t[4] >> 18);
    s[16] = (uint8_t)(t[5]);
    s[17] = (uint8_t)(t[5] >> 8);
    s[18] = (uint8_t)(t[5] >> 16);
    s[19] = (uint8_t)((t[5] >> 24) | (t[6] << 1));
    s[20] = (uint8_t)(t[6] >> 7);
    s[21] = (uint8_t)(t[6] >> 15);
    s[22] = (uint8_t)((t[6] >> 23) | (t[7] << 3));
    s[23] = (uint8_t)(t[7] >> 5);
    s[24] = (uint8_t)(t[7] >> 13);
    s[25] = (uint8_t)((t[7] >> 21) | (t[8] << 4));
    s[26] = (uint8_t)(t[8] >> 4);
    s[27] = (uint8_t)(t[8] >> 12);
    s[28] = (uint8_t)((t[8] >> 20) | (t[9] << 6));
    s[29] = (uint8_t)(t[9] >> 2);
    s[30] = (uint8_t)(t[9] >> 10);
    s[31] = (uint8_t)(t[9] >> 18);
}

void fe_add(fe25519 h, const fe25519 f, const fe25519 g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

void fe_sub(fe25519 h, const fe25519 f, const fe25519 g) {
    for (int i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

void fe_mul(fe25519 h, const fe25519 f, const fe25519 g) {
    // Schoolbook multiplication with reduction
    __int128 t[10] = {0};
    
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 10; j++) {
            int k = i + j;
            __int128 prod = (__int128)f[i] * g[j];
            if (k >= 10) {
                t[k - 10] += prod * 19 * 2;
            } else {
                t[k] += prod;
            }
        }
    }
    
    // Reduce
    for (int i = 0; i < 10; i++) {
        h[i] = (int64_t)(t[i] & ((1LL << 26) - 1));
        if (i < 9) t[i + 1] += t[i] >> 26;
    }
}

void fe_sq(fe25519 h, const fe25519 f) {
    fe_mul(h, f, f);
}

void fe_invert(fe25519 out, const fe25519 z) {
    // Compute z^(p-2) = z^(2^255 - 21) using square-and-multiply
    fe25519 t0, t1, t2, t3;
    
    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (int i = 0; i < 4; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 19; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 0; i < 9; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (int i = 0; i < 99; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (int i = 0; i < 49; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (int i = 0; i < 4; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

// Montgomery ladder for scalar multiplication
void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    std::memcpy(e, scalar, 32);
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    
    fe25519 x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);
    
    // Initialize
    for (int i = 0; i < 10; i++) {
        x2[i] = 0;
        z2[i] = 0;
        x3[i] = x1[i];
        z3[i] = 0;
    }
    x2[0] = 1;
    z3[0] = 1;
    
    int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        int b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;
        
        // Conditional swap
        for (int i = 0; i < 10; i++) {
            int64_t mask = -(int64_t)swap;
            int64_t t = mask & (x2[i] ^ x3[i]);
            x2[i] ^= t; x3[i] ^= t;
            t = mask & (z2[i] ^ z3[i]);
            z2[i] ^= t; z3[i] ^= t;
        }
        swap = b;
        
        // Montgomery ladder step
        fe_sub(tmp0, x3, z3);
        fe_sub(tmp1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, tmp0, x2);
        fe_mul(z2, z2, tmp1);
        fe_sq(tmp0, tmp1);
        fe_sq(tmp1, x2);
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, tmp1, tmp0);
        fe_sub(tmp1, tmp1, tmp0);
        fe_sq(z2, z2);
        fe_mul(z3, tmp1, (const int64_t[]){121666, 0, 0, 0, 0, 0, 0, 0, 0, 0});
        fe_sq(x3, x3);
        fe_add(tmp0, tmp0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, tmp1, tmp0);
    }
    
    // Final swap
    for (int i = 0; i < 10; i++) {
        int64_t mask = -(int64_t)swap;
        int64_t t = mask & (x2[i] ^ x3[i]);
        x2[i] ^= t; x3[i] ^= t;
        t = mask & (z2[i] ^ z3[i]);
        z2[i] ^= t; z3[i] ^= t;
    }
    
    // Compute x2 * z2^(-1)
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(out, x2);
}

// Basepoint (9)
const uint8_t BASEPOINT[32] = {9};

} // anonymous namespace

// Public API
extern "C" void zcrypto_x25519_keygen(uint8_t public_key[32], uint8_t private_key[32]) {
    // Generate random private key
    // In production, use a CSPRNG
    for (int i = 0; i < 32; i++) {
        private_key[i] = (uint8_t)((i * 17 + 42) ^ (i << 3)); // Placeholder - USE REAL RANDOM
    }
    
    // Clamp private key
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    
    // Compute public key = private * basepoint
    x25519_scalarmult(public_key, private_key, BASEPOINT);
}

extern "C" void zcrypto_x25519_shared_secret(
    uint8_t shared_secret[32],
    const uint8_t private_key[32],
    const uint8_t peer_public[32]
) {
    x25519_scalarmult(shared_secret, private_key, peer_public);
}
