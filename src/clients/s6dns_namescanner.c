/* ISC license. */

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-generic-filter.h>

unsigned int s6dns_namescanner (s6dns_domain_t *d, char const *s)
{
  register unsigned int pos = 0 ;
  while (s[pos] && (s[pos] != ' ') && (s[pos] != '\t') && (s[pos] != '\r') && (s[pos] != '\n')) pos++ ;
  if (!s6dns_domain_fromstring_noqualify_encode(d, s, pos)) return 0 ;
  return pos ;
}
