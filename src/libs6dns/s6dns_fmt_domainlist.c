/* ISC license. */

#include <errno.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-fmt.h>

unsigned int s6dns_fmt_domainlist (char *s, unsigned int max, s6dns_domain_t const *list, unsigned int n, char const *delim, unsigned int delimlen)
{
  unsigned int len = 0 ;
  register unsigned int i = 0 ;
  for (; i < n ; i++)
  {
    register unsigned int r = s6dns_domain_tostring(s + len, max - len, list + i) ;
    if (!r) return 0 ;
    len += r ;
    if (i+1 < n)
    {
      if (len + delimlen > max) return (errno = ENAMETOOLONG, 0) ;
      byte_copy(s + len, delimlen, delim) ;
      len += delimlen ;
    }
  }
  return len ;
}
