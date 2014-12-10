/* ISC license. */

#include <s6-dns/s6dns-domain.h>

unsigned int s6dns_domain_encodelist (s6dns_domain_t *list, unsigned int n)
{
  register unsigned int i = 0 ;
  for (; i < n ; i++)
    if (!s6dns_domain_encode(list + i)) break ;
  return i ;
}
