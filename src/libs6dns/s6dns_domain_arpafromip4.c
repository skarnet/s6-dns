/* ISC license. */

#include <string.h>
#include <skalibs/types.h>
#include <s6-dns/s6dns-domain.h>

void s6dns_domain_arpafromip4 (s6dns_domain_t *d, char const *ip)
{
  unsigned int i = 0 ;
  d->len = 0 ;
  d->s[d->len++] = '.' ;  
  for (; i < 4 ; i++)
  {
    unsigned int u = ((unsigned char *)ip)[3-i] ;
    d->len += uint_fmt(d->s + d->len, u) ;
    d->s[d->len++] = '.' ;
  }
  memcpy(d->s + d->len, "in-addr.arpa.", 13) ; d->len += 13 ;
}
