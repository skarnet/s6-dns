/* ISC license. */

#include <stdint.h>

#include <skalibs/uint32.h>

#include "shibari-internal.h"

int shibari_whitelist_ip4_match (diuint32 const *s, size_t len, char const *ip)
{
  uint32_t ip4 ;
  uint32_unpack_big(ip, &ip4) ;
  for (; len-- ; s++) if ((ip4 & s->right) == s->left) return 1 ;
  return 0 ;
}
