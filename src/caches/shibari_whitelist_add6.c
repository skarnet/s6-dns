/* ISC license. */

#include <stdint.h>

#include <skalibs/uint64.h>
#include <skalibs/genalloc.h>

#include "shibari-internal.h"

int shibari_whitelist_add6 (genalloc *g, char const *ip6, uint16_t mask)
{
  shibari_ip6_t shix ;
  if (mask >= 64)
  {
    shix.mask0 = ~(uint64_t)0 ;
    shix.mask1 = ((uint64_t)1 << (mask - 64)) - 1 ;
  }
  else
  {
    shix.mask0 = ((uint64_t)1 << mask) - 1 ;
    shix.mask1 = 0 ;
  }
  uint64_unpack_big(ip6, &shix.addr0) ;
  shix.addr0 &= shix.mask0 ;
  uint64_unpack_big(ip6 + 8, &shix.addr1) ;
  shix.addr1 &= shix.mask1 ;
  return genalloc_append(shibari_ip6_t, g, &shix) ;
}
