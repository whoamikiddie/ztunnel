/**
 * znet.h — ZTunnel Networking Library
 *
 * High-performance C library for UDP batch I/O,
 * bandwidth throttling, and connection pooling.
 * Used via FFI from the Rust relay and client.
 */

#ifndef ZNET_H
#define ZNET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ═══════════════════════════════════════════════════════
 * UDP Engine — Batch packet I/O
 * ═══════════════════════════════════════════════════════ */

/** Opaque UDP engine handle */
typedef struct znet_udp znet_udp_t;

/** UDP packet for batch operations */
typedef struct {
    uint8_t *data;     /**< Packet data buffer */
    size_t   len;      /**< Actual data length */
    size_t   capacity; /**< Buffer capacity */
    uint32_t addr;     /**< Source/dest IPv4 (network order) */
    uint16_t port;     /**< Source/dest port (host order) */
} znet_packet_t;

/**
 * Create a UDP engine bound to the given port.
 * @param port  Port to bind to (0 = ephemeral)
 * @return Handle or NULL on failure
 */
znet_udp_t* znet_udp_bind(uint16_t port);

/**
 * Receive a batch of UDP packets.
 * @param udp      Engine handle
 * @param packets  Pre-allocated packet array
 * @param max_pkts Max packets to receive
 * @return Number of packets received, or -1 on error
 */
int znet_udp_recv_batch(znet_udp_t *udp, znet_packet_t *packets, int max_pkts);

/**
 * Send a batch of UDP packets.
 * @param udp      Engine handle
 * @param packets  Packets to send
 * @param num_pkts Number of packets
 * @return Number of packets sent, or -1 on error
 */
int znet_udp_send_batch(znet_udp_t *udp, znet_packet_t *packets, int num_pkts);

/**
 * Close and free the UDP engine.
 */
void znet_udp_close(znet_udp_t *udp);

/**
 * Allocate a packet buffer.
 * @param capacity  Buffer capacity in bytes
 * @return Initialized packet
 */
znet_packet_t znet_packet_alloc(size_t capacity);

/**
 * Free a packet buffer.
 */
void znet_packet_free(znet_packet_t *pkt);


/* ═══════════════════════════════════════════════════════
 * Bandwidth Throttler — Token bucket algorithm
 * ═══════════════════════════════════════════════════════ */

/** Opaque throttle handle */
typedef struct znet_throttle znet_throttle_t;

/**
 * Create a bandwidth throttler.
 * @param bytes_per_sec  Maximum bytes per second (0 = unlimited)
 * @return Handle or NULL on failure
 */
znet_throttle_t* znet_throttle_create(uint64_t bytes_per_sec);

/**
 * Consume tokens for the given number of bytes.
 * Returns immediately; call znet_throttle_wait() after.
 * @param throttle  Handle
 * @param bytes     Number of bytes to consume
 * @return 0 if tokens available, 1 if must wait
 */
int znet_throttle_consume(znet_throttle_t *throttle, size_t bytes);

/**
 * Wait until tokens are available (blocks the calling thread).
 * Uses nanosecond-precision timing.
 * @param throttle  Handle
 */
void znet_throttle_wait(znet_throttle_t *throttle);

/**
 * Get current throughput in bytes/sec.
 */
uint64_t znet_throttle_get_rate(znet_throttle_t *throttle);

/**
 * Update the rate limit.
 */
void znet_throttle_set_rate(znet_throttle_t *throttle, uint64_t bytes_per_sec);

/**
 * Destroy the throttler.
 */
void znet_throttle_destroy(znet_throttle_t *throttle);


/* ═══════════════════════════════════════════════════════
 * Connection Pool — Pre-allocated TCP connections
 * ═══════════════════════════════════════════════════════ */

/** Opaque connection pool handle */
typedef struct znet_pool znet_pool_t;

/** A pooled connection */
typedef struct {
    int fd;           /**< Socket file descriptor */
    uint32_t addr;    /**< Connected address */
    uint16_t port;    /**< Connected port */
    int in_use;       /**< Currently checked out */
    uint64_t last_used; /**< Timestamp of last use */
} znet_conn_t;

/**
 * Create a connection pool.
 * @param max_conns  Maximum number of connections
 * @param addr       Target address (IPv4)
 * @param port       Target port
 * @return Handle or NULL on failure
 */
znet_pool_t* znet_pool_create(int max_conns, uint32_t addr, uint16_t port);

/**
 * Acquire a connection from the pool.
 * @return Connection or NULL if pool exhausted
 */
znet_conn_t* znet_pool_acquire(znet_pool_t *pool);

/**
 * Release a connection back to the pool.
 */
void znet_pool_release(znet_pool_t *pool, znet_conn_t *conn);

/**
 * Get the number of available connections.
 */
int znet_pool_available(znet_pool_t *pool);

/**
 * Destroy the pool and close all connections.
 */
void znet_pool_destroy(znet_pool_t *pool);


/* ═══════════════════════════════════════════════════════
 * ASM-accelerated timing (x86-64 only)
 * ═══════════════════════════════════════════════════════ */

#ifdef ZNET_HAS_ASM
/**
 * Read the CPU timestamp counter (rdtsc).
 * @return 64-bit cycle count
 */
uint64_t znet_rdtsc(void);

/**
 * CPU pause instruction for efficient busy-wait.
 */
void znet_cpu_pause(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZNET_H */
