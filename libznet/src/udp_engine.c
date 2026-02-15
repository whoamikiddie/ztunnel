/**
 * udp_engine.c — High-performance UDP batch I/O
 *
 * Uses recvmmsg/sendmmsg on Linux for batch packet processing.
 * Falls back to individual recv/send on macOS.
 */

#include "../include/znet.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/** Internal UDP engine state */
struct znet_udp {
  int fd;                  /**< UDP socket */
  struct sockaddr_in addr; /**< Bound address */
  int is_bound;            /**< Whether the socket is bound */
};

znet_udp_t *znet_udp_bind(uint16_t port) {
  znet_udp_t *udp = (znet_udp_t *)calloc(1, sizeof(znet_udp_t));
  if (!udp)
    return NULL;

  udp->fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (udp->fd < 0) {
    free(udp);
    return NULL;
  }

  /* Allow address reuse */
  int opt = 1;
  setsockopt(udp->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  /* Set recv buffer to 4MB for high-throughput */
  int bufsize = 4 * 1024 * 1024;
  setsockopt(udp->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
  setsockopt(udp->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

  memset(&udp->addr, 0, sizeof(udp->addr));
  udp->addr.sin_family = AF_INET;
  udp->addr.sin_addr.s_addr = INADDR_ANY;
  udp->addr.sin_port = htons(port);

  if (bind(udp->fd, (struct sockaddr *)&udp->addr, sizeof(udp->addr)) < 0) {
    close(udp->fd);
    free(udp);
    return NULL;
  }

  udp->is_bound = 1;
  return udp;
}

int znet_udp_recv_batch(znet_udp_t *udp, znet_packet_t *packets, int max_pkts) {
  if (!udp || !packets || max_pkts <= 0)
    return -1;

#ifdef __linux__
  /* Use recvmmsg for batch receive on Linux */
  struct mmsghdr msgs[max_pkts];
  struct iovec iovecs[max_pkts];
  struct sockaddr_in addrs[max_pkts];

  memset(msgs, 0, sizeof(struct mmsghdr) * max_pkts);

  for (int i = 0; i < max_pkts; i++) {
    iovecs[i].iov_base = packets[i].data;
    iovecs[i].iov_len = packets[i].capacity;
    msgs[i].msg_hdr.msg_iov = &iovecs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_name = &addrs[i];
    msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
  }

  int received = recvmmsg(udp->fd, msgs, max_pkts, MSG_DONTWAIT, NULL);
  if (received < 0)
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;

  for (int i = 0; i < received; i++) {
    packets[i].len = msgs[i].msg_len;
    packets[i].addr = ntohl(addrs[i].sin_addr.s_addr);
    packets[i].port = ntohs(addrs[i].sin_port);
  }

  return received;
#else
  /* Fallback: individual recvfrom for macOS/BSD */
  int received = 0;
  for (int i = 0; i < max_pkts; i++) {
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);

    ssize_t n = recvfrom(udp->fd, packets[i].data, packets[i].capacity,
                         MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      return received > 0 ? received : -1;
    }

    packets[i].len = (size_t)n;
    packets[i].addr = ntohl(from.sin_addr.s_addr);
    packets[i].port = ntohs(from.sin_port);
    received++;
  }
  return received;
#endif
}

int znet_udp_send_batch(znet_udp_t *udp, znet_packet_t *packets, int num_pkts) {
  if (!udp || !packets || num_pkts <= 0)
    return -1;

#ifdef __linux__
  /* Use sendmmsg for batch send on Linux */
  struct mmsghdr msgs[num_pkts];
  struct iovec iovecs[num_pkts];
  struct sockaddr_in addrs[num_pkts];

  memset(msgs, 0, sizeof(struct mmsghdr) * num_pkts);

  for (int i = 0; i < num_pkts; i++) {
    addrs[i].sin_family = AF_INET;
    addrs[i].sin_addr.s_addr = htonl(packets[i].addr);
    addrs[i].sin_port = htons(packets[i].port);

    iovecs[i].iov_base = packets[i].data;
    iovecs[i].iov_len = packets[i].len;
    msgs[i].msg_hdr.msg_iov = &iovecs[i];
    msgs[i].msg_hdr.msg_iovlen = 1;
    msgs[i].msg_hdr.msg_name = &addrs[i];
    msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
  }

  int sent = sendmmsg(udp->fd, msgs, num_pkts, 0);
  return sent < 0 ? -1 : sent;
#else
  /* Fallback: individual sendto */
  int sent = 0;
  for (int i = 0; i < num_pkts; i++) {
    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(packets[i].addr);
    to.sin_port = htons(packets[i].port);

    ssize_t n = sendto(udp->fd, packets[i].data, packets[i].len, 0,
                       (struct sockaddr *)&to, sizeof(to));
    if (n < 0)
      return sent > 0 ? sent : -1;
    sent++;
  }
  return sent;
#endif
}

void znet_udp_close(znet_udp_t *udp) {
  if (!udp)
    return;
  if (udp->fd >= 0)
    close(udp->fd);
  free(udp);
}

znet_packet_t znet_packet_alloc(size_t capacity) {
  znet_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.data = (uint8_t *)malloc(capacity);
  pkt.capacity = capacity;
  pkt.len = 0;
  return pkt;
}

void znet_packet_free(znet_packet_t *pkt) {
  if (pkt && pkt->data) {
    free(pkt->data);
    pkt->data = NULL;
    pkt->len = 0;
    pkt->capacity = 0;
  }
}
