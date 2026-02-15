/**
 * throttle.c — Token bucket bandwidth throttler
 *
 * Implements precise bandwidth control using a token bucket
 * algorithm with nanosecond-precision timing.
 */

#include "../include/znet.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

/** Internal throttle state */
struct znet_throttle {
  uint64_t rate_bps;    /**< Bytes per second limit */
  uint64_t tokens;      /**< Available tokens (bytes) */
  uint64_t max_tokens;  /**< Max burst size */
  uint64_t last_refill; /**< Last refill timestamp (ns) */
  uint64_t wait_ns;     /**< How long to wait for tokens (ns) */
};

/** Get monotonic nanosecond timestamp */
static uint64_t now_ns(void) {
#ifdef __APPLE__
  static mach_timebase_info_data_t timebase = {0, 0};
  if (timebase.denom == 0) {
    mach_timebase_info(&timebase);
  }
  return mach_absolute_time() * timebase.numer / timebase.denom;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/** Nanosecond sleep */
static void sleep_ns(uint64_t ns) {
  struct timespec ts;
  ts.tv_sec = (time_t)(ns / 1000000000ULL);
  ts.tv_nsec = (long)(ns % 1000000000ULL);
  nanosleep(&ts, NULL);
}

znet_throttle_t *znet_throttle_create(uint64_t bytes_per_sec) {
  znet_throttle_t *t = (znet_throttle_t *)calloc(1, sizeof(znet_throttle_t));
  if (!t)
    return NULL;

  t->rate_bps = bytes_per_sec;
  /* Allow burst of up to 1 second worth of data */
  t->max_tokens = bytes_per_sec > 0 ? bytes_per_sec : UINT64_MAX;
  t->tokens = t->max_tokens;
  t->last_refill = now_ns();
  t->wait_ns = 0;

  return t;
}

/** Refill tokens based on elapsed time */
static void refill_tokens(znet_throttle_t *t) {
  uint64_t now = now_ns();
  uint64_t elapsed_ns = now - t->last_refill;

  if (elapsed_ns == 0 || t->rate_bps == 0)
    return;

  /* tokens_to_add = elapsed_seconds * rate_bps
   * = elapsed_ns * rate_bps / 1e9 */
  uint64_t tokens_to_add = (elapsed_ns / 1000) * t->rate_bps / 1000000ULL;

  if (tokens_to_add > 0) {
    t->tokens += tokens_to_add;
    if (t->tokens > t->max_tokens) {
      t->tokens = t->max_tokens;
    }
    t->last_refill = now;
  }
}

int znet_throttle_consume(znet_throttle_t *t, size_t bytes) {
  if (!t || t->rate_bps == 0)
    return 0;

  refill_tokens(t);

  if (t->tokens >= bytes) {
    t->tokens -= bytes;
    t->wait_ns = 0;
    return 0; /* Tokens available */
  }

  /* Calculate wait time */
  uint64_t deficit = bytes - t->tokens;
  /* wait_ns = deficit / rate_bps * 1e9 */
  t->wait_ns = deficit * 1000000000ULL / t->rate_bps;
  return 1; /* Must wait */
}

void znet_throttle_wait(znet_throttle_t *t) {
  if (!t || t->wait_ns == 0)
    return;

  if (t->wait_ns < 1000) {
    /* Sub-microsecond: busy-wait with pause */
#ifdef ZNET_HAS_ASM
    uint64_t start = znet_rdtsc();
    /* Approximate: assume ~3GHz CPU, so 1ns ≈ 3 cycles */
    uint64_t target = start + t->wait_ns * 3;
    while (znet_rdtsc() < target) {
      znet_cpu_pause();
    }
#else
    /* C fallback: just yield */
    struct timespec ts = {0, 1000}; /* 1µs minimum */
    nanosleep(&ts, NULL);
#endif
  } else {
    sleep_ns(t->wait_ns);
  }

  /* Refill after waiting */
  refill_tokens(t);
  t->wait_ns = 0;
}

uint64_t znet_throttle_get_rate(znet_throttle_t *t) {
  return t ? t->rate_bps : 0;
}

void znet_throttle_set_rate(znet_throttle_t *t, uint64_t bytes_per_sec) {
  if (!t)
    return;
  t->rate_bps = bytes_per_sec;
  t->max_tokens = bytes_per_sec > 0 ? bytes_per_sec : UINT64_MAX;
  if (t->tokens > t->max_tokens) {
    t->tokens = t->max_tokens;
  }
}

void znet_throttle_destroy(znet_throttle_t *t) { free(t); }
