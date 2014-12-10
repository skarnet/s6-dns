/* ISC license. */

#include <errno.h>
#include <s6-dns/s6dns-domain.h>

int s6dns_domain_noqualify (s6dns_domain_t *d)
{
  if (d->s[d->len-1] != '.')
  {
    if (d->len == 255) return (errno = ENAMETOOLONG, 0) ;
    d->s[d->len++] = '.' ;
  }
  return 1 ;
}
