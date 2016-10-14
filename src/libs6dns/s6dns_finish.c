/* ISC license. */

#include <s6dns/s6-dns.h>

void s6dns_finish ()
{
  s6dns_engine_free(&s6dns_engine_here) ;
  s6dns_rci_free(&s6dns_rci_here) ;
}
