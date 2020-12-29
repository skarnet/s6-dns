/* ISC license. */

#include <skalibs/alloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <s6-dns/dcache.h>
#include "dcache-internal.h"

void dcache_delete (dcache_t *z, uint32_t i)
{
  dcache_node_t *y = DNODE(z, i) ;
  avltree_delete(&z->by_expire, &y->expire) ;
  avltree_delete(&z->by_entry, &y->entry) ;
  avltree_delete(&z->by_key, &y->key) ;
  alloc_free(y->key.s) ;
  z->size -= DCACHE_NODE_OVERHEAD + y->key.len + y->datalen ;
  gensetdyn_delete(&z->storage, i) ;
}
