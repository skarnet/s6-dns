/* ISC license. */

#include <errno.h>

#include <skalibs/error.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

static int addit (genalloc *ips, char const *s, size_t len, int is6)
{
  size_t base = genalloc_len(ip46full_t, ips) ;
  size_t n = len >> (is6 ? 4 : 2) ;
  ip46full_t *p ;
  if (!genalloc_readyplus(ip46full_t, ips, n)) return 0 ;
  p = genalloc_s(ip46full_t, ips) + base ;
  for (size_t i = 0 ; i < n ; i++)
    if (is6) ip46full_from_ip6(p + i, s + (i << 4)) ;
    else ip46full_from_ip4(p + i, s + (i << 2)) ;
  genalloc_setlen(ip46full_t, ips, base + n) ;
  return 1 ;
}

int s6dns_resolveq_aaaaa_r (genalloc *ips, char const *name, size_t len, s6dns_rci_t const *rci, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  s6dns_engine_t dtl[rci->rulesnum << 1] ;
  stralloc data = STRALLOC_ZERO ;
  unsigned int best = 0 ;
  unsigned int n ;
  int e = 0 ;
  int ans = 0 ;
  int pinned = 0 ;
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
        if (pinned && !(best & 1)) goto end ;
        if (best >= n << 1) goto notfound ;
        if (error_isagain(dtl[best].status)) break ;
        if (dtl[best].status) { errno = dtl[best].status ; goto err ; }
        r = s6dns_message_parse(&h, s6dns_engine_packet(dtl + best), s6dns_engine_packetlen(dtl + best), (best & 1) ? &s6dns_message_parse_answer_a : s6dns_message_parse_answer_aaaa, &data) ;
        if (r < 0) goto err ;
        else if (r)
        {
          if (!addit(ips, data.s, data.len, !(best & 1))) goto err ;
          if (r > 1) ans |= 1 + !(best & 1) ;
          data.len = 0 ;
          pinned = 1 ;
        }
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

 notfound:
  errno = e ;
  ans = 0 ;
  goto end ;
 err:
  ans = -1 ;
 end:
  stralloc_free(&data) ;
  s6dns_engine_freen(dtl, n<<1) ;
  return ans ;
}
