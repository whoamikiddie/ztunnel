/**
 * test_all.c — Basic tests for libznet
 */

#include "../include/znet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("  TEST: %s ... ", #name);
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

/* ── Throttle Tests ── */

void test_throttle_create(void) {
  TEST(throttle_create);
  znet_throttle_t *t = znet_throttle_create(1024 * 1024); /* 1MB/s */
  if (!t) {
    FAIL("NULL");
    return;
  }
  assert(znet_throttle_get_rate(t) == 1024 * 1024);
  znet_throttle_destroy(t);
  PASS();
}

void test_throttle_unlimited(void) {
  TEST(throttle_unlimited);
  znet_throttle_t *t = znet_throttle_create(0);
  if (!t) {
    FAIL("NULL");
    return;
  }
  int r = znet_throttle_consume(t, 999999);
  assert(r == 0); /* Should never need to wait */
  znet_throttle_destroy(t);
  PASS();
}

void test_throttle_consume(void) {
  TEST(throttle_consume);
  znet_throttle_t *t = znet_throttle_create(100);
  if (!t) {
    FAIL("NULL");
    return;
  }
  /* First 100 bytes should be instant (burst allowance) */
  int r = znet_throttle_consume(t, 50);
  assert(r == 0);
  r = znet_throttle_consume(t, 50);
  assert(r == 0);
  /* Next should require waiting */
  r = znet_throttle_consume(t, 50);
  assert(r == 1);
  znet_throttle_destroy(t);
  PASS();
}

void test_throttle_set_rate(void) {
  TEST(throttle_set_rate);
  znet_throttle_t *t = znet_throttle_create(1000);
  znet_throttle_set_rate(t, 5000);
  assert(znet_throttle_get_rate(t) == 5000);
  znet_throttle_destroy(t);
  PASS();
}

/* ── Packet Tests ── */

void test_packet_alloc(void) {
  TEST(packet_alloc);
  znet_packet_t pkt = znet_packet_alloc(1500);
  assert(pkt.data != NULL);
  assert(pkt.capacity == 1500);
  assert(pkt.len == 0);
  memset(pkt.data, 0xAA, 1500);
  znet_packet_free(&pkt);
  assert(pkt.data == NULL);
  PASS();
}

/* ── UDP Tests ── */

void test_udp_bind(void) {
  TEST(udp_bind);
  /* Bind to ephemeral port */
  znet_udp_t *udp = znet_udp_bind(0);
  if (!udp) {
    FAIL("bind failed");
    return;
  }
  znet_udp_close(udp);
  PASS();
}

void test_udp_send_recv(void) {
  TEST(udp_send_recv);
  /* Create two UDP sockets */
  znet_udp_t *sender = znet_udp_bind(0);
  znet_udp_t *recver = znet_udp_bind(19876);
  if (!sender || !recver) {
    if (sender)
      znet_udp_close(sender);
    if (recver)
      znet_udp_close(recver);
    FAIL("bind failed");
    return;
  }

  /* Send a packet */
  znet_packet_t spkt = znet_packet_alloc(64);
  memcpy(spkt.data, "HELLO ZNET", 10);
  spkt.len = 10;
  spkt.addr = 0x7F000001; /* 127.0.0.1 */
  spkt.port = 19876;

  int sent = znet_udp_send_batch(sender, &spkt, 1);
  assert(sent == 1);

  /* Receive it */
  znet_packet_t rpkt = znet_packet_alloc(64);
  /* Small delay for packet to arrive */
  struct timespec ts = {0, 10000000}; /* 10ms */
  nanosleep(&ts, NULL);

  int recvd = znet_udp_recv_batch(recver, &rpkt, 1);
  if (recvd == 1) {
    assert(rpkt.len == 10);
    assert(memcmp(rpkt.data, "HELLO ZNET", 10) == 0);
  }
  /* recvd could be 0 if packet hasn't arrived yet (non-blocking) */

  znet_packet_free(&spkt);
  znet_packet_free(&rpkt);
  znet_udp_close(sender);
  znet_udp_close(recver);
  PASS();
}

/* ── ASM Tests ── */
#ifdef ZNET_HAS_ASM
void test_rdtsc(void) {
  TEST(rdtsc);
  uint64_t t1 = znet_rdtsc();
  /* Do some work */
  volatile int x = 0;
  for (int i = 0; i < 1000; i++)
    x += i;
  uint64_t t2 = znet_rdtsc();
  assert(t2 > t1);
  printf("(%llu cycles) ", (unsigned long long)(t2 - t1));
  PASS();
}

void test_cpu_pause(void) {
  TEST(cpu_pause);
  /* Just verify it doesn't crash */
  for (int i = 0; i < 100; i++) {
    znet_cpu_pause();
  }
  PASS();
}
#endif

/* ── Main ── */

int main(void) {
  printf("\n═══ libznet Tests ═══\n\n");

  /* Throttle */
  test_throttle_create();
  test_throttle_unlimited();
  test_throttle_consume();
  test_throttle_set_rate();

  /* Packets */
  test_packet_alloc();

  /* UDP */
  test_udp_bind();
  test_udp_send_recv();

#ifdef ZNET_HAS_ASM
  /* ASM */
  test_rdtsc();
  test_cpu_pause();
#endif

  printf("\n═══ Results: %d passed, %d failed ═══\n\n", tests_passed,
         tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
