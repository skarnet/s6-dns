/* ISC license. */

#include <skalibs/alloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#include <s6-dns/dcache.h>

static dcache_t const dcache_zero = DCACHE_ZERO ;

static void dcache_node_free (void *p)
{
  alloc_free(((dcache_node_t *)p)->key.s) ;
}

void dcache_free (dcache_t *z)
{
  avltree_free(&z->by_expire) ;
  avltree_free(&z->by_entry) ;
  avltree_free(&z->by_key) ;
  gensetdyn_deepfree(&z->storage, &dcache_node_free) ;
  *z = dcache_zero ;
}
