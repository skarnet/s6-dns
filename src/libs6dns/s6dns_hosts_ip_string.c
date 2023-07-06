/* ISC license. */

#include <errno.h>
#include <string.h>

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/hosts.h>

#include <skalibs/posixishard.h>

extern int s6dns_hosts_ip_string_r (cdb const *c, char const *name, stralloc *sa, unsigned int flags)
{
  s6dns_domain_t d ;
  int r ;
  cdb_data data ;
  if (!c->map) return 0 ;
  if (!s6dns_domain_fromstring(&d, name, strlen(name))
   || !s6dns_domain_noqualify(&d)) return -1 ;

  {
    char tmp[3 + d.len] ;
    tmp[0] = flags & 2 ? 'u' : 'a' ;
    tmp[1] = flags & 1 ? '6' : '4' ;
    tmp[2] = ':' ;
    memcpy(tmp + 3, d.s, d.len) ;
    r = cdb_find(c, &data, tmp, 3 + d.len) ;
  }
  if (r <= 0) return r ;
  if (!data.len) return 0 ;
  if (data.len & (flags & 1 ? 15 : 3)) return (errno = EPROTO, -1) ;
  if (!stralloc_catb(sa, data.s, data.len)) return -1 ;
  return data.len >> (flags & 1 ? 4 : 2) ;
}
