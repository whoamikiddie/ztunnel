# throttle_x64.S — x86-64 ASM timing intrinsics for libznet
#
# Provides rdtsc-based cycle counting and CPU pause instruction
# for sub-microsecond busy-wait in the bandwidth throttler.
#
# These are called from throttle.c when ZNET_HAS_ASM is defined.

    .text
    .globl _znet_rdtsc
    .globl  znet_rdtsc
    .globl _znet_cpu_pause
    .globl  znet_cpu_pause

# ═══════════════════════════════════════════════════════════
# uint64_t znet_rdtsc(void)
#
# Read the Time Stamp Counter (TSC).
# Uses RDTSCP for serialized (non-speculative) reads.
# Returns: RAX = 64-bit cycle count
# ═══════════════════════════════════════════════════════════
    .p2align 4
_znet_rdtsc:
znet_rdtsc:
    # RDTSCP: serializing read of TSC
    # EDX:EAX = timestamp, ECX = processor ID (ignored)
    rdtscp

    # Combine EDX:EAX into RAX
    # RAX already has low 32 bits from RDTSCP
    shl     $32, %rdx
    or      %rdx, %rax

    ret

# ═══════════════════════════════════════════════════════════
# void znet_cpu_pause(void)
#
# Execute the PAUSE instruction for efficient busy-waiting.
# PAUSE:
#   - Hints the CPU we're in a spin-wait loop
#   - Reduces power consumption during spin
#   - Avoids memory order violation pipeline flush
#   - ~10 cycles on modern CPUs
# ═══════════════════════════════════════════════════════════
    .p2align 4
_znet_cpu_pause:
znet_cpu_pause:
    pause
    ret
