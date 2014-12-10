/* ISC license. */

#include <skalibs/bytestr.h>
#include <skalibs/uint.h>
#include <s6-dns/s6dns-domain.h>

void s6dns_domain_arpafromip4 (s6dns_domain_t *d, char const *ip)
{
  register unsigned int i = 0 ;
  d->len = 0 ;
  d->s[d->len++] = '.' ;  
  for (; i < 4 ; i++)
  {
    register unsigned int u = ((unsigned char *)ip)[3-i] ;
    d->len += uint_fmt(d->s + d->len, u) ;
    d->s[d->len++] = '.' ;
  }
  byte_copy(d->s + d->len, 13, "in-addr.arpa.") ; d->len += 13 ;
}
