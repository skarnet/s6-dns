/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-rci.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolveq_aaaaa_r (genalloc *ips, char const *name, size_t len, s6dns_rci_t const *rci, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  s6dns_engine_t dtl[rci->rulesnum << 1] ;
  stralloc data = STRALLOC_ZERO ;
  unsigned int best = 0 ;
  unsigned int n ;
  int e = 0 ;
  unsigned int i = 0 ;
  {
    s6dns_domain_t domains[rci->rulesnum] ;
    n = s6dns_domain_fromstring_qualify_encode(domains, name, len, rci->rules.s, rci->rulesnum) ;
    if (!n) return -1 ;
    for (; i < n ; i++)
    {
      dtl[i<<1] = s6dns_engine_zero ;
      if (!s6dns_engine_init_r(dtl + (i<<1), &rci->servers, S6DNS_O_RECURSIVE, domains[i].s, domains[i].len, S6DNS_T_AAAA, dbh, deadline, stamp))
      {
        s6dns_engine_freen(dtl, i<<1) ;
        return -1 ;
      }
      dtl[(i<<1)+1] = s6dns_engine_zero ;
      if (!s6dns_engine_init_r(dtl + (i<<1) + 1, &rci->servers, S6DNS_O_RECURSIVE, domains[i].s, domains[i].len, S6DNS_T_A, dbh, deadline, stamp))
      {
        s6dns_engine_freen(dtl, (i<<1)+1) ;
        return -1 ;
      }
    }
  }

  for (;;)
  {
    int k = s6dns_resolven_loop(dtl, n << 1, 1, deadline, stamp) ;
    if (k < 0) goto err ;
    if ((unsigned int)k == best)
    {
      for (;; best++)
      {
        s6dns_message_header_t h ;
        int r ;
        if (best >= n << 1) goto notfound ;
        if (error_isagain(dtl[best].status)) break ;
        if (dtl[best].status) { errno = dtl[best].status ; goto err ; }
        r = s6dns_message_parse(&h, s6dns_engine_packet(dtl + best), s6dns_engine_packetlen(dtl + best), (best & 1) ? &s6dns_message_parse_answer_a : s6dns_message_parse_answer_aaaa, &data) ;
        if (r < 0) goto err ;
        else if (r) goto found ;
        else switch (errno)
        {
          case EBUSY :
          case ENOENT :
          case ECONNREFUSED :
          case EIO :
            break ;
          default : goto err ;
        }
        if (!best) e = errno ;
      }
    }
  }

 found:
  s6dns_engine_freen(dtl, n<<1) ;
  {
    size_t len = data.len >> ((best & 1) ? 2 : 4) ;
    size_t i = 0 ;
    size_t base = genalloc_len(ip46_t, ips) ;
    if (!genalloc_readyplus(ip46_t, ips, len)) return -1 ;
    for (; i < len ; i++)
      ip46_from_ip(genalloc_s(ip46_t, ips) + base + i, data.s + (i << ((best & 1) ? 2 : 4)), !(best & 1)) ;
    genalloc_setlen(ip46_t, ips, base + len) ;
  }
  stralloc_free(&data) ;
  return 1 ;

 notfound:
  s6dns_engine_freen(dtl, n<<1) ;
  return (errno = e, 0) ;

 err:
  s6dns_engine_freen(dtl, n<<1) ;
  return -1 ;
}
