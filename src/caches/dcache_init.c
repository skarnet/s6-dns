/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/uint64.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <s6-dns/dcache.h>

static int key_cmp (void const *a, void const *b, void *x)
{
  dcache_key_t const *ka = a ;
  dcache_key_t const *kb = b ;
  if (ka->len < kb->len) return -1 ;
  if (kb->len < ka->len) return 1 ;
  (void)x ;
  return memcmp(ka->s, kb->s, ka->len) ;
}

static int tain_cmp (void const *a, void const *b, void *x)
{
  tain_t const *ta = a ;
  tain_t const *tb = b ;
  (void)x ;
  return tain_less(ta, tb) ? -1 : tain_less(tb, ta) ;
}

static void *key_dtok (uint32_t d, void *x)
{
  return &GENSETDYN_P(dcache_node_t, (gensetdyn *)x, d)->key ;
}

static void *entry_dtok (uint32_t d, void *x)
{
  return &GENSETDYN_P(dcache_node_t, (gensetdyn *)x, d)->entry ;
}

static void *expire_dtok (uint32_t d, void *x)
{
  return &GENSETDYN_P(dcache_node_t, (gensetdyn *)x, d)->expire ;
}


void dcache_init (dcache_t *z, uint64_t max)
{
  gensetdyn_init(&z->storage, sizeof(dcache_node_t), max >> 9, 3, 8) ;
  avltree_init(&z->by_key, max >> 9, 3, 8, &key_dtok, &key_cmp, &z->storage) ;
  avltree_init(&z->by_entry, max >> 9, 3, 8, &entry_dtok, &tain_cmp, &z->storage) ;
  avltree_init(&z->by_expire, max >> 9, 3, 8, &expire_dtok, &tain_cmp, &z->storage) ;
  z->size = 0 ;
  z->motion = 0 ;
}
