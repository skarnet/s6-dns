/* ISC license. */

#include <s6-dns/s6dns-rci.h>
#include <s6-dns/s6dns.h>

int s6dns_init (void)
{
  if (!s6dns_rci_init(&s6dns_rci_here, "/etc/resolv.conf")) return 0 ;
  return 1 ;
}
