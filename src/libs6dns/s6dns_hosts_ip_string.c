/* ISC license. */

#include <errno.h>

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/hosts.h>

#include <skalibs/posixishard.h>

extern int s6dns_hosts_ip_string_r (cdb const *c, char const *name, stralloc *sa, unsigned int flags)
{
  s6dns_domain_t d ;
  cdb_data data ;
  if (!c->map) return 0 ;
  if (!s6dns_domain_fromstring(&d, name, strlen(name))) return -1 ;
  if (!(flags & 2) && !s6dns_domain_noqualify(&d)) return -1 ;
  {
    int r ;
    char tmp[4 + d.len] ;
    tmp[0] = flags & 2 ? 'u' : 'a' ;
    tmp[1] = flags & 1 ? '6' : '4' ;
    tmp[2] = ':' ;
    r = s6dns_domain_tostring(tmp + 3, d.len + 1, &d) ;
    tmp[3 + r] = 0 ;
    if (!r) return -1 ;
    r = cdb_find(c, &data, tmp, 3 + r) ;
    if (r <= 0) return r ;
  }
  if (!data.len) return 0 ;
  if (data.len & (flags & 1 ? 15 : 3)) return (errno = EPROTO, -1) ;
  if (!stralloc_catb(sa, data.s, data.len)) return -1 ;
  return data.len >> (flags & 1 ? 4 : 2) ;
}
