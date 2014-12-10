/* ISC license. */

#include <errno.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-domain.h>

unsigned int s6dns_domain_tostring (char *s, unsigned int max, s6dns_domain_t const *d)
{
  if ((unsigned int)d->len + 1 > max) return (errno = ENAMETOOLONG, 0) ;
  if (!d->len || (d->s[0] != '.')) return (errno = EINVAL, 0) ;
  if (d->len == 1)
  {
    s[0] = '.' ;
    return 1 ;
  }
  else
  {
    byte_copy(s, d->len - 1, d->s + 1) ;
    return d->len - 1 ;
  }
}
