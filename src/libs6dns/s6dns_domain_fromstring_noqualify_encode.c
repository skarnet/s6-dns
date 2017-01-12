/* ISC license. */

#include <sys/types.h>
#include <s6-dns/s6dns-domain.h>

int s6dns_domain_fromstring_noqualify_encode (s6dns_domain_t *d, char const *name, size_t len)
{
  return s6dns_domain_fromstring(d, name, len)
   && s6dns_domain_noqualify(d)
   && s6dns_domain_encode(d) ;
}
