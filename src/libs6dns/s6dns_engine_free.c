/* ISC license. */

#include <skalibs/stralloc.h>
#include <s6-dns/s6dns-engine.h>

void s6dns_engine_free (s6dns_engine_t *dt)
{
  s6dns_engine_recycle(dt) ;
  stralloc_free(&dt->sa) ;
  *dt = s6dns_engine_zero ;
}
