/* ISC license. */

#include <stdint.h>

#include <skalibs/tai.h>
#include <skalibs/avltree.h>

#include <s6-dns/dcache.h>
#include "dcache-internal.h"

void dcache_clean_expired (dcache_t *z, tain_t const *stamp)
{
  for (;;)
  {
    uint32_t i ;
    if (!avltree_min(&z->by_expire, &i)) break ;
    if (tain_less(stamp, &DNODE(z, i)->expire)) break ;
    dcache_delete(z, i) ;
  }
}
