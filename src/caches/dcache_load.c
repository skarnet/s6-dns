/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/uint16.h>
#include <skalibs/uint64.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>

#include <s6-dns/dcache.h>

static inline int dcache_load_node (dcache_t *z, uint64_t max, buffer *b)
{
  tain_t entry = { .nano = 0 } ;
  tain_t expire = { .nano = 0 } ;
  uint16_t keylen ;
  uint16_t datalen ;
  char pack[TAI_PACK * 2 + 4] ;
  ssize_t r = buffer_get(b, pack, TAI_PACK * 2 + 4) ;
  if (!r) return 0 ;
  if (r < TAI_PACK * 2 + 4) return -1 ;
  tai_unpack(pack, tain_secp(&entry)) ;
  tai_unpack(pack + TAI_PACK, tain_secp(&expire)) ;
  uint16_unpack_big(pack + TAI_PACK * 2, &keylen) ;
  uint16_unpack_big(pack + TAI_PACK * 2 + 2, &datalen) ;
  {
    uint32_t len = (uint32_t)keylen + (uint32_t)datalen ;
    char blob[len+1] ;  /* 128 kB max, it's ok */ 
    r = buffer_get(b, blob, len+1) ;
    if (!r) return (errno = EPIPE, -1) ;
    if (r < len) return -1 ;
    if (blob[len]) return (errno = EPROTO, -1) ;
    if (!dcache_add(z, max, blob, keylen, blob + keylen, datalen, &expire, &entry)) return -1 ;
  }
  return 1 ;
}

static inline int dcache_load_from_buffer (dcache_t *z, uint64_t max, buffer *b)
{
  {
    char banner[sizeof(DCACHE_MAGIC) - 1] ;
    char pack[8] ;
    if (buffer_get(b, banner, sizeof(DCACHE_MAGIC) - 1) < sizeof(DCACHE_MAGIC) - 1)
      return 0 ;
    if (memcmp(banner, DCACHE_MAGIC, sizeof(DCACHE_MAGIC) - 1)) return 0 ;
    if (buffer_get(b, pack, 8) < 8) return 0 ;
    uint64_unpack_big(pack, &z->size) ;
    if (buffer_get(b, pack, 8) < 8) return 0 ;
    uint64_unpack_big(pack, &z->motion) ;
  }
  for (;;)
  {
    int r = dcache_load_node(z, max, b) ;
    if (r < 0) return 0 ;
    if (!r) break ;
  }
  return 1 ;
}

#define N 8192

int dcache_load (dcache_t *z, uint64_t max, char const *file)
{
  char buf[N] ;
  buffer b ;
  int fd = open_readb(file) ;
  if (fd == -1) return 0 ;
  buffer_init(&b, &buffer_read, fd, buf, N) ;
  if (!dcache_load_from_buffer(z, max, &b)) goto err ;
  fd_close(fd) ;
  return 1 ;

 err:
  dcache_free(z) ;
  fd_close(fd) ;
  return 0 ;
}
