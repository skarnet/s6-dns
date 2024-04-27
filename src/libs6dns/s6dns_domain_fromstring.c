/* ISC license. */

#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <s6-dns/s6dns-domain.h>

int s6dns_domain_fromstring (s6dns_domain_t *d, char const *s, size_t len)
{
  size_t j = 1 ;
  size_t i = 0 ;
  unsigned int lastdot = 0 ;
  d->s[0] = '.' ;
  for (; i < len ; i++)
  {
    if (lastdot)
    {
      if ((j >= 255) || (lastdot++ >= 64)) return (errno = ENAMETOOLONG, 0) ;
      d->s[j++] = tolower(s[i]) ;
    }
    if (s[i] == '.') lastdot = 0 ;
    else if (!lastdot)
    {
      i-- ;
      lastdot = 1 ;
    }
  }
  d->len = j ;
  return 1 ;
}
