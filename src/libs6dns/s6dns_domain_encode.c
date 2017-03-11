/* ISC license. */

#include <errno.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-domain.h>

int s6dns_domain_encode (s6dns_domain_t *d)
{
  char *s = d->s ;
  unsigned int len = d->len ;
  if (!d->len || (*s != '.')) return (errno = EINVAL, 0) ;
  while (len > 1)
  {
    unsigned int n = byte_chr(s + 1, len - 1, '.') ;
    if (n > 63) return (errno = EINVAL, 0) ;
    *s = n++ ; s += n ; len -= n ;
  }
  if (!len) return (errno = EINVAL, 0) ;
  *s = 0 ;
  return 1 ;
}
