/* ISC license. */

#include <string.h>
#include <errno.h>
#include <s6-dns/s6dns-domain.h>

unsigned int s6dns_domain_qualify (s6dns_domain_t *list, s6dns_domain_t const *d, char const *rules, unsigned int rulesnum)
{
  if (!d->len) return (errno = EINVAL, 0) ;
  if (d->s[d->len - 1] == '.')
  {
    list[0] = *d ;
    return 1 ;
  }
  else
  {
    unsigned int i = 0 ;
    for (; i < rulesnum ; i++)
    {
      size_t n = strlen(rules) ;
      if (d->len + n >= 254) return (errno = ENAMETOOLONG, 0) ;
      list[i] = *d ;
      list[i].s[d->len] = '.' ;
      memcpy(list[i].s + d->len + 1, rules, n) ;
      list[i].len += n+1 ;
      rules += n+1 ;
    }
    return i ;
  }
}
