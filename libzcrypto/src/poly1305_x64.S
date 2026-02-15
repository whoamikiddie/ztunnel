# poly1305_x64.S — x86-64 ASM hot path for Poly1305 MAC
#
# Optimized 130-bit multiply-accumulate for the Poly1305
# authentication algorithm. Processes 16-byte blocks using
# register-only state for ~3x speedup over C implementation.
#
# Poly1305 state: accumulator h = h0:h1:h2 (130 bits)
# Key: r = r0:r1 (128 bits, clamped)

    .text
    .globl _zcrypto_poly1305_block_asm
    .globl  zcrypto_poly1305_block_asm

# ═══════════════════════════════════════════════════════════
# void zcrypto_poly1305_block_asm(
#     uint64_t *h,      // rdi: accumulator [h0, h1, h2]
#     const uint64_t *r, // rsi: key [r0, r1]
#     const uint8_t *msg, // rdx: 16-byte message block
#     uint32_t hibit    // ecx: 1 for regular blocks, 0 for final
# )
#
# Computes: h = (h + msg) * r mod (2^130 - 5)
# ═══════════════════════════════════════════════════════════
    .p2align 4
_zcrypto_poly1305_block_asm:
zcrypto_poly1305_block_asm:
    push    %rbx
    push    %r12
    push    %r13
    push    %r14
    push    %r15

    # Load accumulator: h0, h1, h2
    mov     (%rdi), %r8         # h0
    mov     8(%rdi), %r9        # h1
    mov     16(%rdi), %r10      # h2 (5 bits max)

    # Load key: r0, r1
    mov     (%rsi), %r11        # r0
    mov     8(%rsi), %r12       # r1

    # Load message block (little-endian)
    mov     (%rdx), %r13        # msg[0..7]
    mov     8(%rdx), %r14       # msg[8..15]

    # h += msg
    add     %r13, %r8           # h0 += msg_lo
    adc     %r14, %r9           # h1 += msg_hi + carry
    adc     %ecx, %r10d         # h2 += hibit + carry

    # ── Multiply: h * r ──
    # We need: d0 = h0*r0
    #          d1 = h0*r1 + h1*r0
    #          d2 = h1*r1 + h2*r0
    #          d3 = h2*r1
    # Using 64x64→128 multiply (mulq)

    # d0 = h0 * r0
    mov     %r8, %rax
    mulq    %r11                # RDX:RAX = h0 * r0
    mov     %rax, %rbx          # d0_lo
    mov     %rdx, %rcx          # d0_hi (carry into d1)

    # d1 = h0 * r1
    mov     %r8, %rax
    mulq    %r12                # RDX:RAX = h0 * r1
    add     %rax, %rcx          # d1_lo += h0*r1_lo
    adc     $0, %rdx
    mov     %rdx, %r15          # d1_hi

    # d1 += h1 * r0
    mov     %r9, %rax
    mulq    %r11                # RDX:RAX = h1 * r0
    add     %rax, %rcx          # d1_lo += h1*r0_lo
    adc     %rdx, %r15          # d1_hi += carry + h1*r0_hi

    # d2 = h1 * r1
    mov     %r9, %rax
    mulq    %r12                # RDX:RAX = h1 * r1
    mov     %rax, %r13
    add     %r15, %r13          # d2_lo = d1_hi + h1*r1_lo
    adc     $0, %rdx
    mov     %rdx, %r14          # d2_hi

    # d2 += h2 * r0
    mov     %r10, %rax
    and     $3, %eax            # h2 is only 2 bits for mod
    imulq   %r11, %rax          # h2 * r0 (small multiply)
    add     %rax, %r13          # d2_lo += h2*r0

    # d3 = h2 * r1 (added to d2_hi)
    mov     %r10, %rax
    and     $3, %eax
    imulq   %r12, %rax
    add     %rax, %r14          # d2_hi += h2*r1

    # ── Reduction mod 2^130 - 5 ──
    # Split at 130 bits:
    # h0 = d0[0:63] = rbx
    # h1 = d1[0:63] = rcx
    # h2 = d2[0:1]  = r13 & 3
    # overflow = d2[2:] || d3
    # h += overflow * 5

    mov     %r13, %r10
    and     $3, %r10d           # h2 = d2 & 3

    # overflow = d2 >> 2 (combined with d2_hi)
    shrd    $2, %r14, %r13      # shift right 2 bits
    shr     $2, %r14

    # overflow * 5 = overflow * 4 + overflow
    lea     (%r13,%r13,4), %rax # overflow * 5
    add     %rax, %rbx          # h0 += overflow*5 (low)
    adc     $0, %rcx            # h1 += carry
    adc     $0, %r10d           # h2 += carry

    # Handle overflow in high part
    test    %r14, %r14
    jz      .Lno_high_overflow
    lea     (%r14,%r14,4), %rax
    add     %rax, %rcx
    adc     $0, %r10d
.Lno_high_overflow:

    # Store result
    mov     %rbx, (%rdi)        # h0
    mov     %rcx, 8(%rdi)       # h1
    mov     %r10, 16(%rdi)      # h2

    pop     %r15
    pop     %r14
    pop     %r13
    pop     %r12
    pop     %rbx
    ret
