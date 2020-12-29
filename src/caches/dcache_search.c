/* ISC license. */

#include <stdint.h>

#include <skalibs/avltree.h>

#include <s6-dns/dcache.h>
#include "dcache-internal.h"

dcache_node_t *dcache_search (dcache_t *z, char const *key, uint16_t keylen)
{
  uint32_t i ;
  dcache_key_t k = { .s = (char *)key, .len = keylen } ;
  return avltree_search(&z->by_key, &k, &i) ? DNODE(z, i) : 0 ;
}
