/* ISC license. */

#include <string.h>

#include <skalibs/ip46.h>
#include <skalibs/genalloc.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/hosts.h>

extern int s6dns_hosts_aaaaa_q_r (cdb const *c, char const *name, genalloc *ga, char const *rules, unsigned int rulesnum)
{
  int r ;
  int gawn = !genalloc_s(ip46full, ga) ;
  size_t gabase = genalloc_len(ip46full, ga) ;
  s6dns_domain_t d[rulesnum + 1] ;
  if (!c->map) return 0 ;
  r = s6dns_hosts_aaaaa_unq_r(c, name, ga) ;
  if (r == -1) return -1 ;
  if (!s6dns_domain_fromstring(d + rulesnum, name, strlen(name))) goto err ;
  if (!s6dns_domain_qualify(d, d + rulesnum, rules, rulesnum)) goto err ;
  for (unsigned int i = 0 ; i < rulesnum ; i++)
  {
    char tmp[256] ;
    r = s6dns_domain_tostring(tmp, 256, d + i) ;
    if (!r) goto err ;
    tmp[r] = 0 ;
    r = s6dns_hosts_aaaaa_noq_r(c, tmp, ga) ;
    if (r == -1) goto err ;
    if (r) break ;
  }
  return genalloc_len(ip46full, ga) - gabase ;

 err:
  if (gawn) genalloc_free(ip46full, ga) ; else genalloc_setlen(ip46full, ga, gabase) ;
  return -1 ;
}
