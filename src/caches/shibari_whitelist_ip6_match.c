/* ISC license. */

#include <stdint.h>

#include <skalibs/uint64.h>

#include "shibari-internal.h"

int shibari_whitelist_ip6_match (shibari_ip6_t const *s, size_t len, char const *ip)
{
  uint64_t addr0, addr1 ;
  uint64_unpack_big(ip, &addr0) ;
  uint64_unpack_big(ip + 8, &addr1) ;
  for (; len-- ; s++) if ((addr0 & s->mask0) == s->addr0 && (addr1 & s->mask1) == s->addr1) return 1 ;
  return 0 ;
}
