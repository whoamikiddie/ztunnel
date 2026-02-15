/**
 * connpool.c — Pre-allocated TCP connection pool
 *
 * Maintains a pool of warm TCP connections to local services,
 * reducing connection setup latency for repeated requests.
 */

#include "../include/znet.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/** Internal pool state */
struct znet_pool {
  znet_conn_t *conns;   /**< Connection array */
  int max_conns;        /**< Pool capacity */
  uint32_t target_addr; /**< Target address */
  uint16_t target_port; /**< Target port */
  int active_count;     /**< Current active connections */
};

/** Get timestamp in milliseconds */
static uint64_t ms_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/** Connect a single socket to the target */
static int connect_socket(uint32_t addr, uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  /* Set TCP_NODELAY for low latency */
  int flag = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

  /* Set non-blocking for connect with timeout */
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);

  struct sockaddr_in target;
  memset(&target, 0, sizeof(target));
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = htonl(addr);
  target.sin_port = htons(port);

  int ret = connect(fd, (struct sockaddr *)&target, sizeof(target));
  if (ret < 0 && errno != EINPROGRESS) {
    close(fd);
    return -1;
  }

  /* Wait for connection with timeout (100ms) */
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(fd, &wfds);
  struct timeval tv = {0, 100000}; /* 100ms */

  ret = select(fd + 1, NULL, &wfds, NULL, &tv);
  if (ret <= 0) {
    close(fd);
    return -1;
  }

  /* Check for connection error */
  int err = 0;
  socklen_t errlen = sizeof(err);
  getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
  if (err != 0) {
    close(fd);
    return -1;
  }

  /* Restore blocking mode */
  fcntl(fd, F_SETFL, flags);

  return fd;
}

/** Check if a connection is still alive */
static int is_alive(int fd) {
  char buf;
  int ret = recv(fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
  if (ret == 0)
    return 0; /* Closed */
  if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    return 0;
  return 1;
}

znet_pool_t *znet_pool_create(int max_conns, uint32_t addr, uint16_t port) {
  znet_pool_t *pool = (znet_pool_t *)calloc(1, sizeof(znet_pool_t));
  if (!pool)
    return NULL;

  pool->conns = (znet_conn_t *)calloc(max_conns, sizeof(znet_conn_t));
  if (!pool->conns) {
    free(pool);
    return NULL;
  }

  pool->max_conns = max_conns;
  pool->target_addr = addr;
  pool->target_port = port;
  pool->active_count = 0;

  /* Initialize all connections as invalid */
  for (int i = 0; i < max_conns; i++) {
    pool->conns[i].fd = -1;
    pool->conns[i].in_use = 0;
    pool->conns[i].addr = addr;
    pool->conns[i].port = port;
  }

  /* Pre-warm a few connections */
  int warm = max_conns < 4 ? max_conns : 4;
  for (int i = 0; i < warm; i++) {
    int fd = connect_socket(addr, port);
    if (fd >= 0) {
      pool->conns[i].fd = fd;
      pool->conns[i].last_used = ms_now();
      pool->active_count++;
    }
  }

  return pool;
}

znet_conn_t *znet_pool_acquire(znet_pool_t *pool) {
  if (!pool)
    return NULL;

  /* Find an available warm connection */
  for (int i = 0; i < pool->max_conns; i++) {
    if (pool->conns[i].fd >= 0 && !pool->conns[i].in_use) {
      /* Verify the connection is still alive */
      if (is_alive(pool->conns[i].fd)) {
        pool->conns[i].in_use = 1;
        pool->conns[i].last_used = ms_now();
        return &pool->conns[i];
      } else {
        /* Connection died, close it */
        close(pool->conns[i].fd);
        pool->conns[i].fd = -1;
        pool->active_count--;
      }
    }
  }

  /* No warm connections available, create a new one */
  for (int i = 0; i < pool->max_conns; i++) {
    if (pool->conns[i].fd < 0) {
      int fd = connect_socket(pool->target_addr, pool->target_port);
      if (fd >= 0) {
        pool->conns[i].fd = fd;
        pool->conns[i].in_use = 1;
        pool->conns[i].last_used = ms_now();
        pool->active_count++;
        return &pool->conns[i];
      }
    }
  }

  return NULL; /* Pool exhausted */
}

void znet_pool_release(znet_pool_t *pool, znet_conn_t *conn) {
  if (!pool || !conn)
    return;
  conn->in_use = 0;
  conn->last_used = ms_now();
}

int znet_pool_available(znet_pool_t *pool) {
  if (!pool)
    return 0;
  int avail = 0;
  for (int i = 0; i < pool->max_conns; i++) {
    if (!pool->conns[i].in_use && (pool->conns[i].fd >= 0)) {
      avail++;
    }
  }
  return avail;
}

void znet_pool_destroy(znet_pool_t *pool) {
  if (!pool)
    return;
  for (int i = 0; i < pool->max_conns; i++) {
    if (pool->conns[i].fd >= 0) {
      close(pool->conns[i].fd);
    }
  }
  free(pool->conns);
  free(pool);
}
