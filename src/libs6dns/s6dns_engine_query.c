/* ISC license. */

#include <skalibs/uint16.h>

#include <s6-dns/s6dns-engine.h>

void s6dns_engine_query (s6dns_engine_t const *dt, char **q, uint16_t *qlen, uint16_t *qtype)
{
  uint16_t len ;
  uint16_unpack_big(dt->sa.s, &len) ;
  *q = dt->sa.s + 14 ;
  *qlen = len - 16 ;
  uint16_unpack_big(dt->sa.s + len - 2, qtype) ;
}
