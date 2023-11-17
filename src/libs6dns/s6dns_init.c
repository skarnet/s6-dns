/* ISC license. */

#include <s6-dns/s6dns-rci.h>
#include <s6-dns/hosts.h>
#include <s6-dns/s6dns.h>

int s6dns_init_options (uint32_t options)
{
  if (!s6dns_rci_init(&s6dns_rci_here, "/etc/resolv.conf")) return 0 ;
  if (options & 1 && s6dns_hosts_init(&s6dns_hosts_here, "/etc/hosts", "/etc/hosts.cdb", "/tmp/hosts.cdb") == -1) goto err ;
  return 1 ;

 err:
  s6dns_rci_free(&s6dns_rci_here) ;
  return 0 ;
}
