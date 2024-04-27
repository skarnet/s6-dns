/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>

#include <s6-dns/s6dns-domain.h>

static inline unsigned int s6dns_domain_label_decode (char *s, unsigned int max)
{
  unsigned int len = *(unsigned char *)s ;
  if ((len > 63) || (len >= max)) return (errno = EPROTO, 0) ;
  *s = '.' ;
  return len + 1 ;
}

int s6dns_domain_decode (s6dns_domain_t *d)
{
  unsigned int max = 255 ;
  unsigned int pos = 0 ;
  for (;;)
  {
    unsigned int r = s6dns_domain_label_decode(d->s + pos, max - pos) ;
    if (!r) return 0 ;
    pos += r ;
    if (r == 1) break ;
  }
  d->len = pos ;
  return 1 ;
}
