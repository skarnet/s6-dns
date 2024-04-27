/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/bytestr.h>

#include <s6-dns/s6dns-domain.h>

unsigned int s6dns_domain_tostring (char *s, size_t max, s6dns_domain_t const *d)
{
  if ((size_t)d->len + 1 > max) return (errno = ENAMETOOLONG, 0) ;
  if (!d->len || (d->s[0] != '.')) return (errno = EINVAL, 0) ;
  if (d->len == 1)
  {
    s[0] = '.' ;
    s[1] = 0 ;
    return 1 ;
  }
  else
  {
    memcpy(s, d->s + 1, d->len - 1) ;
    s[d->len - 1] = 0 ;
    case_lowerb(s, d->len - 1) ;
    return d->len - 1 ;
  }
}
