/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/uint64.h>
#include <skalibs/alloc.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avlnode.h>
#include <skalibs/avltree.h>

#include <s6-dns/dcache.h>
#include "dcache-internal.h"

static void uniquify (avltree const *tree, tain *stamp)
{
  static tain const nano = { .sec = TAI_ZERO, .nano = 1 } ;
  uint32_t dummy ;
  while (avltree_search(tree, stamp, &dummy))
    tain_add(stamp, stamp, &nano) ;
}

static inline void dcache_gc_by_entry (dcache_t *z, uint64_t max)
{
  while (z->size > max)
  {
    uint32_t oldest ;
    if (!avltree_min(&z->by_entry, &oldest)) break ;
    dcache_delete(z, oldest) ;
  }
}

static inline int dcache_add_node (dcache_t *z, dcache_node_t const *node)
{
  uint32_t i ;
  dcache_node_t *y ;
  if (!gensetdyn_new(&z->storage, &i)) return 0 ;
  y = DNODE(z, i) ; *y = *node ;
  uniquify(&z->by_entry, &y->entry) ;
  uniquify(&z->by_expire, &y->expire) ;
  if (!avltree_insert(&z->by_key, i)) goto err1 ;
  if (!avltree_insert(&z->by_entry, i)) goto err2 ;
  if (!avltree_insert(&z->by_expire, i)) goto err3 ;
  return 1 ;

 err3:
  avltree_delete(&z->by_entry, &y->entry) ;
 err2:
  avltree_delete(&z->by_key, &y->key) ;
 err1:
  gensetdyn_delete(&z->storage, i) ;
  return 0 ;
}

static inline int dcache_add_unbounded (dcache_t *z, char const *key, uint16_t keylen, char const *data, uint16_t datalen, tain const *expire, tain const *stamp)
{
  uint32_t len = (uint32_t)keylen + (uint32_t)datalen ;
  dcache_node_t y = { .key = { .s = alloc(len) } } ;
  if (!y.key.s) return 0 ;
  memcpy(y.key.s, key, keylen) ;
  memcpy(y.key.s + keylen, data, datalen) ;
  y.key.len = keylen ;
  y.datalen = datalen ;
  y.entry = *stamp ;
  y.expire = *expire ;
  if (!dcache_add_node(z, &y))
  {
    alloc_free(y.key.s) ;
    return 0 ;
  }
  z->size += DCACHE_NODE_OVERHEAD + len ;
  z->motion += DCACHE_NODE_OVERHEAD + len ;
  return 1 ;
}


int dcache_add (dcache_t *z, uint64_t max, char const *key, uint16_t keylen, char const *data, uint16_t datalen, tain const *expire, tain const *stamp)
{
  uint64_t size = DCACHE_NODE_OVERHEAD + keylen + datalen ;
  if (size > max) return (errno = EINVAL, 0) ;
  if (z->size > max - size) dcache_clean_expired(z, stamp) ;
  if (z->size > max - size) dcache_gc_by_entry(z, max - size) ;
  return dcache_add_unbounded(z, key, keylen, data, datalen, expire, stamp) ;
}
