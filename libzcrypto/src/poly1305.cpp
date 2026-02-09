/**
 * Poly1305 MAC Implementation
 * 
 * One-time authenticator using 128-bit key.
 */

#include "zcrypto.hpp"
#include <cstring>

namespace {

// Poly1305 state
struct Poly1305State {
    uint32_t r[5];  // Key part (clamped)
    uint32_t h[5];  // Accumulator
    uint32_t pad[4]; // Key part 2
};

void poly1305_init(Poly1305State& st, const uint8_t key[32]) {
    // r = key[0..15] with clamping
    st.r[0] = ((uint32_t)key[0] | ((uint32_t)key[1] << 8) | 
               ((uint32_t)key[2] << 16) | ((uint32_t)key[3] << 24)) & 0x0fffffff;
    st.r[1] = (((uint32_t)key[3] >> 2) | ((uint32_t)key[4] << 6) | 
               ((uint32_t)key[5] << 14) | ((uint32_t)key[6] << 22)) & 0x0ffffffc;
    st.r[2] = (((uint32_t)key[6] >> 4) | ((uint32_t)key[7] << 4) | 
               ((uint32_t)key[8] << 12) | ((uint32_t)key[9] << 20)) & 0x0ffffffc;
    st.r[3] = (((uint32_t)key[9] >> 6) | ((uint32_t)key[10] << 2) | 
               ((uint32_t)key[11] << 10) | ((uint32_t)key[12] << 18)) & 0x0ffffffc;
    st.r[4] = ((uint32_t)key[13] | ((uint32_t)key[14] << 8) | 
               ((uint32_t)key[15] << 16)) & 0x00fffff;

    // h = 0
    st.h[0] = st.h[1] = st.h[2] = st.h[3] = st.h[4] = 0;

    // pad = key[16..31]
    st.pad[0] = (uint32_t)key[16] | ((uint32_t)key[17] << 8) | 
                ((uint32_t)key[18] << 16) | ((uint32_t)key[19] << 24);
    st.pad[1] = (uint32_t)key[20] | ((uint32_t)key[21] << 8) | 
                ((uint32_t)key[22] << 16) | ((uint32_t)key[23] << 24);
    st.pad[2] = (uint32_t)key[24] | ((uint32_t)key[25] << 8) | 
                ((uint32_t)key[26] << 16) | ((uint32_t)key[27] << 24);
    st.pad[3] = (uint32_t)key[28] | ((uint32_t)key[29] << 8) | 
                ((uint32_t)key[30] << 16) | ((uint32_t)key[31] << 24);
}

void poly1305_blocks(Poly1305State& st, const uint8_t* data, size_t len, bool final) {
    const uint32_t hibit = final ? 0 : (1 << 24);
    
    while (len >= 16) {
        uint64_t t0, t1, t2, t3, t4;
        uint64_t d0, d1, d2, d3, d4;
        
        // h += m[i]
        t0 = (uint32_t)data[0] | ((uint32_t)data[1] << 8) | 
             ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        t1 = (uint32_t)data[4] | ((uint32_t)data[5] << 8) | 
             ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 24);
        t2 = (uint32_t)data[8] | ((uint32_t)data[9] << 8) | 
             ((uint32_t)data[10] << 16) | ((uint32_t)data[11] << 24);
        t3 = (uint32_t)data[12] | ((uint32_t)data[13] << 8) | 
             ((uint32_t)data[14] << 16) | ((uint32_t)data[15] << 24);
        
        st.h[0] += (uint32_t)(t0 & 0x3ffffff);
        st.h[1] += (uint32_t)((t0 >> 26) | ((t1 & 0xfffff) << 6));
        st.h[2] += (uint32_t)((t1 >> 20) | ((t2 & 0x3fff) << 12));
        st.h[3] += (uint32_t)((t2 >> 14) | ((t3 & 0xff) << 18));
        st.h[4] += (uint32_t)(t3 >> 8) | hibit;
        
        // h *= r (modular multiplication)
        d0 = ((uint64_t)st.h[0] * st.r[0]) + 
             ((uint64_t)st.h[1] * (st.r[4] * 5)) +
             ((uint64_t)st.h[2] * (st.r[3] * 5)) +
             ((uint64_t)st.h[3] * (st.r[2] * 5)) +
             ((uint64_t)st.h[4] * (st.r[1] * 5));
        
        d1 = ((uint64_t)st.h[0] * st.r[1]) +
             ((uint64_t)st.h[1] * st.r[0]) +
             ((uint64_t)st.h[2] * (st.r[4] * 5)) +
             ((uint64_t)st.h[3] * (st.r[3] * 5)) +
             ((uint64_t)st.h[4] * (st.r[2] * 5));
        
        d2 = ((uint64_t)st.h[0] * st.r[2]) +
             ((uint64_t)st.h[1] * st.r[1]) +
             ((uint64_t)st.h[2] * st.r[0]) +
             ((uint64_t)st.h[3] * (st.r[4] * 5)) +
             ((uint64_t)st.h[4] * (st.r[3] * 5));
        
        d3 = ((uint64_t)st.h[0] * st.r[3]) +
             ((uint64_t)st.h[1] * st.r[2]) +
             ((uint64_t)st.h[2] * st.r[1]) +
             ((uint64_t)st.h[3] * st.r[0]) +
             ((uint64_t)st.h[4] * (st.r[4] * 5));
        
        d4 = ((uint64_t)st.h[0] * st.r[4]) +
             ((uint64_t)st.h[1] * st.r[3]) +
             ((uint64_t)st.h[2] * st.r[2]) +
             ((uint64_t)st.h[3] * st.r[1]) +
             ((uint64_t)st.h[4] * st.r[0]);
        
        // Reduce
        uint32_t c;
        c = (uint32_t)(d0 >> 26); st.h[0] = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); st.h[1] = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); st.h[2] = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); st.h[3] = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); st.h[4] = (uint32_t)d4 & 0x3ffffff;
        st.h[0] += c * 5; c = st.h[0] >> 26; st.h[0] &= 0x3ffffff;
        st.h[1] += c;
        
        data += 16;
        len -= 16;
    }
}

void poly1305_finish(Poly1305State& st, uint8_t tag[16], const uint8_t* data, size_t remaining) {
    // Process remaining bytes with padding
    if (remaining > 0) {
        uint8_t block[16] = {0};
        std::memcpy(block, data, remaining);
        block[remaining] = 1;
        poly1305_blocks(st, block, 16, true);
    }
    
    // Final reduction and output
    uint64_t f0, f1, f2, f3;
    uint32_t g0, g1, g2, g3, g4, mask;
    
    // Fully reduce h
    uint32_t c = st.h[1] >> 26; st.h[1] &= 0x3ffffff;
    st.h[2] += c; c = st.h[2] >> 26; st.h[2] &= 0x3ffffff;
    st.h[3] += c; c = st.h[3] >> 26; st.h[3] &= 0x3ffffff;
    st.h[4] += c; c = st.h[4] >> 26; st.h[4] &= 0x3ffffff;
    st.h[0] += c * 5; c = st.h[0] >> 26; st.h[0] &= 0x3ffffff;
    st.h[1] += c;
    
    // Compute h + -p
    g0 = st.h[0] + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = st.h[1] + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = st.h[2] + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = st.h[3] + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = st.h[4] + c - (1 << 26);
    
    // Select h if h < p, or h + -p if h >= p
    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    st.h[0] = (st.h[0] & mask) | g0;
    st.h[1] = (st.h[1] & mask) | g1;
    st.h[2] = (st.h[2] & mask) | g2;
    st.h[3] = (st.h[3] & mask) | g3;
    st.h[4] = (st.h[4] & mask) | g4;
    
    // h = h + pad
    f0 = ((uint64_t)st.h[0] | ((uint64_t)st.h[1] << 26)) + st.pad[0];
    f1 = ((uint64_t)st.h[1] >> 6) | ((uint64_t)st.h[2] << 20);
    f2 = ((uint64_t)st.h[2] >> 12) | ((uint64_t)st.h[3] << 14);
    f3 = ((uint64_t)st.h[3] >> 18) | ((uint64_t)st.h[4] << 8);
    
    f1 += st.pad[1] + (f0 >> 32); f0 &= 0xffffffff;
    f2 += st.pad[2] + (f1 >> 32); f1 &= 0xffffffff;
    f3 += st.pad[3] + (f2 >> 32); f2 &= 0xffffffff;
    
    // Output
    tag[0] = (uint8_t)f0; tag[1] = (uint8_t)(f0 >> 8);
    tag[2] = (uint8_t)(f0 >> 16); tag[3] = (uint8_t)(f0 >> 24);
    tag[4] = (uint8_t)f1; tag[5] = (uint8_t)(f1 >> 8);
    tag[6] = (uint8_t)(f1 >> 16); tag[7] = (uint8_t)(f1 >> 24);
    tag[8] = (uint8_t)f2; tag[9] = (uint8_t)(f2 >> 8);
    tag[10] = (uint8_t)(f2 >> 16); tag[11] = (uint8_t)(f2 >> 24);
    tag[12] = (uint8_t)f3; tag[13] = (uint8_t)(f3 >> 8);
    tag[14] = (uint8_t)(f3 >> 16); tag[15] = (uint8_t)(f3 >> 24);
}

} // anonymous namespace

// Public API
void poly1305_auth(uint8_t tag[16], const uint8_t* msg, size_t len, const uint8_t key[32]) {
    Poly1305State st;
    poly1305_init(st, key);
    
    size_t full_blocks = len & ~15;
    if (full_blocks > 0) {
        poly1305_blocks(st, msg, full_blocks, false);
    }
    
    poly1305_finish(st, tag, msg + full_blocks, len - full_blocks);
    
    zcrypto_memzero(&st, sizeof(st));
}
