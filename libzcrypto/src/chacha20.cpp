/**
 * ChaCha20 Stream Cipher Implementation
 * 
 * This implementation uses x86-64 SIMD (AVX2) for the core quarter-round
 * operations when available.
 */

#include "zcrypto.hpp"
#include <cstring>

namespace {

// ChaCha20 constants: "expand 32-byte k"
constexpr uint32_t CONSTANTS[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Quarter round operation
inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

// ChaCha20 block function (C++ fallback)
void chacha20_block_generic(uint32_t output[16], const uint32_t input[16]) {
    uint32_t x[16];
    std::memcpy(x, input, 64);
    
    // 20 rounds (10 double-rounds)
    for (int i = 0; i < 10; i++) {
        // Column rounds
        quarter_round(x[0], x[4], x[8],  x[12]);
        quarter_round(x[1], x[5], x[9],  x[13]);
        quarter_round(x[2], x[6], x[10], x[14]);
        quarter_round(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        quarter_round(x[0], x[5], x[10], x[15]);
        quarter_round(x[1], x[6], x[11], x[12]);
        quarter_round(x[2], x[7], x[8],  x[13]);
        quarter_round(x[3], x[4], x[9],  x[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        output[i] = x[i] + input[i];
    }
}

#ifdef ZCRYPTO_USE_ASM
// Defined in chacha20_x64.S
extern "C" void chacha20_block_avx2(uint32_t output[16], const uint32_t input[16]);
#define chacha20_block chacha20_block_avx2
#else
#define chacha20_block chacha20_block_generic
#endif

} // anonymous namespace

// ChaCha20 encryption/decryption (symmetric)
extern "C" void chacha20_encrypt(
    uint8_t* output,
    const uint8_t* input,
    size_t len,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter
) {
    uint32_t state[16];
    uint32_t block[16];
    
    // Initialize state
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];
    
    // Key (8 words)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = 
            (uint32_t)key[i * 4 + 0] |
            ((uint32_t)key[i * 4 + 1] << 8) |
            ((uint32_t)key[i * 4 + 2] << 16) |
            ((uint32_t)key[i * 4 + 3] << 24);
    }
    
    // Counter
    state[12] = counter;
    
    // Nonce (3 words)
    for (int i = 0; i < 3; i++) {
        state[13 + i] = 
            (uint32_t)nonce[i * 4 + 0] |
            ((uint32_t)nonce[i * 4 + 1] << 8) |
            ((uint32_t)nonce[i * 4 + 2] << 16) |
            ((uint32_t)nonce[i * 4 + 3] << 24);
    }
    
    // Encrypt/decrypt
    size_t offset = 0;
    while (offset < len) {
        chacha20_block(block, state);
        
        size_t chunk = (len - offset < 64) ? (len - offset) : 64;
        const uint8_t* keystream = reinterpret_cast<const uint8_t*>(block);
        
        for (size_t i = 0; i < chunk; i++) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
        
        offset += chunk;
        state[12]++; // Increment counter
    }
    
    // Zero sensitive data
    zcrypto_memzero(state, sizeof(state));
    zcrypto_memzero(block, sizeof(block));
}
