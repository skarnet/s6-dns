/* ISC license. */

#include <errno.h>
#include <string.h>

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-dns/hosts.h>

#include <skalibs/posixishard.h>

int s6dns_hosts_name_r (cdb const *c, char const *ip, stralloc *sa, genalloc *ga, int is6)
{
  int r ;
  cdb_data data ;
  int sawn = !sa->s ;
  int gawn = !genalloc_s(size_t, ga) ;
  size_t sabase = sa->len ;
  size_t gabase = genalloc_len(size_t, ga) ;
  size_t i = sabase ;
  char tmp[19] = "p4:" ;
  if (!c->map) return 0 ;
  if (is6) tmp[1] = '6' ;
  memcpy(tmp + 3, ip, is6 ? 16 : 4) ;
  r = cdb_find(c, &data, tmp, 7) ;
  if (r <= 0) return r ;
  if (!data.len) return 0 ;
  if (data.s[data.len - 1]) return (errno = EPROTO, -1) ;
  if (!stralloc_catb(sa, data.s, data.len)) return -1 ;
  while (i < sa->len)
  {
    if (!genalloc_catb(size_t, ga, &i, 1)) goto err ;
    i += strlen(sa->s + i) + 1 ;
  }
  return genalloc_len(size_t, ga) - gabase ;

 err:
  if (gawn) genalloc_free(size_t, ga) ; else genalloc_setlen(size_t, ga, 0) ;
  if (sawn) stralloc_free(sa) ; else sa->len = 0 ;
  return -1 ;
}
