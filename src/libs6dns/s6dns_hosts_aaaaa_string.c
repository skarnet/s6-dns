/* ISC license. */

#include <errno.h>
#include <string.h>

#include <skalibs/ip46.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-dns/hosts.h>

extern int s6dns_hosts_aaaaa_string_r (cdb const *c, char const *name, genalloc *ga, int isunq)
{
  stralloc sa = STRALLOC_ZERO ;
  int gawn = !genalloc_s(ip46full, ga) ;
  size_t gabase = genalloc_len(ip46full, ga) ;
  int r = s6dns_hosts_a_string_r(c, name, &sa, isunq) ;
  if (r <= 0) return r ;
  if (!genalloc_readyplus(ip46full, ga, r)) return -1 ;
  for (size_t i = 0 ; i < r ; i++)
    ip46full_from_ip4(genalloc_s(ip46full, ga) + i, sa.s + (i << 2)) ;
  genalloc_setlen(ip46full, ga, gabase + r) ;
  sa.len = 0 ;
  r = s6dns_hosts_aaaa_string_r(c, name, &sa, isunq) ;
  if (r == -1) goto err ;
  if (r)
  {
    if (!genalloc_readyplus(ip46full, ga, r)) goto err ;
    for (size_t i = 0 ; i < r ; i++)
      ip46full_from_ip6(genalloc_s(ip46full, ga) + i, sa.s + (i << 4)) ;
    genalloc_setlen(ip46full, ga, genalloc_len(ip46full, ga) + r) ;
  }
  stralloc_free(&sa) ;
  return genalloc_len(ip46full, ga) - gabase ;

 err:
  if (gawn) genalloc_free(ip46full, ga) ; else genalloc_setlen(ip46full, ga, gabase) ;
  stralloc_free(&sa) ;
  return -1 ;
}
