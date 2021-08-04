/* ISC license. */

#include <skalibs/tai.h>
#include <s6-dns/s6dns-engine.h>

void s6dns_engine_nextdeadline (s6dns_engine_t const *dt, tain *deadline)
{
  if (tain_less(&dt->deadline, deadline)) *deadline = dt->deadline ;
  if (tain_less(&dt->localdeadline, deadline)) *deadline = dt->localdeadline ;
}
