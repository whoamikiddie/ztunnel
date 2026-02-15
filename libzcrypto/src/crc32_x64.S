# crc32_x64.S — Hardware-accelerated CRC32C using SSE4.2
#
# Uses the CRC32Q instruction for 8-byte-at-a-time processing.
# Falls back to byte-by-byte for tail bytes.
# Used for fast packet integrity checks in libznet.

    .text
    .globl _zcrypto_crc32c_asm
    .globl  zcrypto_crc32c_asm

# ═══════════════════════════════════════════════════════════
# uint32_t zcrypto_crc32c_asm(
#     uint32_t crc,       // edi: initial CRC value
#     const uint8_t *buf, // rsi: data buffer
#     size_t len          // rdx: buffer length
# )
#
# Returns: 32-bit CRC32C checksum
# ═══════════════════════════════════════════════════════════
    .p2align 4
_zcrypto_crc32c_asm:
zcrypto_crc32c_asm:
    # Use RAX for the running CRC (wider register for crc32q)
    mov     %edi, %eax          # crc
    mov     %rsi, %rcx          # buf pointer
    mov     %rdx, %r8           # len

    # Process 8 bytes at a time using CRC32Q
    cmp     $8, %r8
    jb      .Lcrc_tail

    .p2align 4
.Lcrc_8byte_loop:
    crc32q  (%rcx), %rax        # CRC32C of 8 bytes
    add     $8, %rcx
    sub     $8, %r8
    cmp     $8, %r8
    jae     .Lcrc_8byte_loop

.Lcrc_tail:
    # Process remaining bytes one at a time
    test    %r8, %r8
    jz      .Lcrc_done

    .p2align 4
.Lcrc_1byte_loop:
    crc32b  (%rcx), %eax        # CRC32C of 1 byte
    inc     %rcx
    dec     %r8
    jnz     .Lcrc_1byte_loop

.Lcrc_done:
    # Return CRC in EAX (already there)
    ret
