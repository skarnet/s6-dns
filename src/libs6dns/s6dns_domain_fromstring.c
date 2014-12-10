/* ISC license. */

#include <errno.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-domain.h>

int s6dns_domain_fromstring (s6dns_domain_t *d, char const *s, unsigned int len)
{
  register unsigned int j = 1 ;
  register unsigned int i = 0 ;
  register unsigned int lastdot = 0 ;
  d->s[0] = '.' ;
  for (; i < len ; i++)
  {
    if (lastdot)
    {
      if ((j >= 255) || (lastdot++ >= 64)) return (errno = ENAMETOOLONG, 0) ;
      d->s[j++] = s[i] ;
    }
    if (s[i] == '.') lastdot = 0 ;
    else if (!lastdot)
    {
      i-- ;
      lastdot = 1 ;
    }
  }
  case_lowerb(d->s + 1, j-1) ;
  d->len = j ;
  return 1 ;
}
