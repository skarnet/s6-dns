/* ISC license. */

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include <skalibs/posixplz.h>
#include <skalibs/uint16.h>
#include <skalibs/uint64.h>
#include <skalibs/buffer.h>
#include <skalibs/stralloc.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/skamisc.h>
#include <skalibs/gensetdyn.h>

#include <s6-dns/dcache.h>

static int write_node_iter (char *data, void *aux)
{
  dcache_node_t *y = (dcache_node_t *)data ;
  buffer *b = aux ;
  char pack[TAI_PACK * 2 + 4] ;
  tai_pack(pack, tain_secp(&y->entry)) ;
  tai_pack(pack + TAI_PACK, tain_secp(&y->expire)) ;
  uint16_pack(pack + TAI_PACK * 2, y->key.len) ;
  uint16_pack(pack + TAI_PACK * 2 + 2, y->datalen) ;
  if (buffer_put(b, pack, TAI_PACK * 2 + 4) == -1) return 0 ;
  if (buffer_put(b, y->key.s, y->key.len + y->datalen) == -1) return 0 ;
  if (buffer_put(b, "", 1) == -1) return 0 ;
  return 1 ;
}

static inline int dcache_save_to_buffer (dcache_t const *z, buffer *b)
{
  char pack[16] ;
  if (buffer_puts(b, DCACHE_MAGIC) == -1) return 0 ;
  uint64_pack_big(pack, z->size) ;
  uint64_pack_big(pack + 8, z->motion) ;
  if (buffer_put(b, pack, 16) < 16) return 0 ;

 /* XXX: can gensetdyn_iter blow up the stack if z->storage is huge? */
  if (gensetdyn_iter_nocancel((gensetdyn *)&z->storage, gensetdyn_n(&z->storage), &write_node_iter, b) < gensetdyn_n(&z->storage)) return 0 ;

  return buffer_flush(b) ;
}

#define N 8192

int dcache_save (dcache_t const *z, char const *file)
{
  stralloc sa = STRALLOC_ZERO ;
  int fd ;
  buffer b ;
  char buf[N] ;
  if (!stralloc_cats(&sa, file)) return 0 ;
  if (!sauniquename(&sa) || !stralloc_0(&sa)) goto err0 ;
  fd = open_excl(sa.s) ;
  if (fd == -1) goto err0 ;
  buffer_init(&b, &buffer_write, fd, buf, N) ;
  if (!dcache_save_to_buffer(z, &b) || fsync(fd) < 0) goto err2 ;
  fd_close(fd) ;
  if (rename(sa.s, file) == -1) goto err1 ;
  stralloc_free(&sa) ;
  return 1 ;

 err2:
  fd_close(fd) ;
 err1:
  unlink_void(sa.s) ;
 err0:
  stralloc_free(&sa) ;
  return 0 ;
}
