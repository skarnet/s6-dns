/* ISC license. */

#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-rci.h>
#include <s6-dns/s6dns.h>

void s6dns_finish ()
{
  s6dns_engine_free(&s6dns_engine_here) ;
  s6dns_hosts_free(&s6dns_hosts_here) ;
  s6dns_rci_free(&s6dns_rci_here) ;
}
