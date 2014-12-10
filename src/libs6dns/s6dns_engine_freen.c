/* ISC license. */

#include <s6-dns/s6dns-engine.h>

void s6dns_engine_freen (s6dns_engine_t *dtl, unsigned int n)
{
  while (n--) s6dns_engine_free(dtl + n) ;
}
