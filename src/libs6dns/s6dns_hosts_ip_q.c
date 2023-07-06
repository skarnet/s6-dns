/* ISC license. */

#include <string.h>

#include <skalibs/stralloc.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/hosts.h>

extern int s6dns_hosts_ip_q_r (cdb const *c, char const *name, stralloc *sa, char const *rules, unsigned int rulesnum, int is6)
{
  int r ;
  int sawn = !sa->s ;
  size_t sabase = sa->len ;
  s6dns_domain_t d[rulesnum + 1] ;
  if (!c->map) return 0 ;
  r = s6dns_hosts_ip_unq_r(c, name, sa, is6) ;
  if (r == -1) return -1 ;
  if (!s6dns_domain_fromstring(d + rulesnum, name, strlen(name))) goto err ;
  if (!s6dns_domain_qualify(d, d + rulesnum, rules, rulesnum)) goto err ;
  for (unsigned int i = 0 ; i < rulesnum ; i++)
  {
    char tmp[256] ;
    r = s6dns_domain_tostring(tmp, 256, d + i) ;
    if (!r) goto err ;
    tmp[r] = 0 ;
    r = s6dns_hosts_ip_noq_r(c, tmp, sa, is6) ;
    if (r == -1) goto err ;
    if (r) break ;
  }
  return (sa->len - sabase) >> (is6 ? 4 : 2) ;

 err:
  if (sawn) stralloc_free(sa) ; else sa->len = sabase ;
  return -1 ;
}
