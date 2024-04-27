/* ISC license. */

#include <string.h>
#include <errno.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-fmt.h>

size_t s6dns_fmt_domainlist (char *s, size_t max, s6dns_domain_t const *list, unsigned int n, char const *delim, size_t delimlen)
{
  size_t len = 0 ;
  unsigned int i = 0 ;
  for (; i < n ; i++)
  {
    unsigned int r = s6dns_domain_tostring(s + len, max - len, list + i) ;
    if (!r) return 0 ;
    len += r ;
    if (i+1 < n)
    {
      if (len + delimlen > max) return (errno = ENAMETOOLONG, 0) ;
      memcpy(s + len, delim, delimlen) ;
      len += delimlen ;
    }
  }
  return len ;
}
