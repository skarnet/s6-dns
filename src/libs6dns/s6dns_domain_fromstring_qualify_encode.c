/* ISC license. */

#include <s6-dns/s6dns-domain.h>

unsigned int s6dns_domain_fromstring_qualify_encode (s6dns_domain_t *list, char const *name, size_t len, char const *rules, unsigned int rulesnum)
{
  s6dns_domain_t d ;
  if (!s6dns_domain_fromstring(&d, name, len)) return 0 ;
  return s6dns_domain_encodelist(list, s6dns_domain_qualify(list, &d, rules, rulesnum)) ;
}
