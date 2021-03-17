/* ISC license. */

#include <errno.h>

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/ip46.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolvenoq_aaaaa_r (genalloc *ips, char const *name, size_t len, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  stralloc sa[2] = { STRALLOC_ZERO, STRALLOC_ZERO } ;
  s6dns_resolve_t blob[2] ;
  if (!s6dns_domain_fromstring_noqualify_encode(&blob[0].q, name, len)) return -1 ;
  blob[0].qtype = S6DNS_T_AAAA ;
  blob[0].options = S6DNS_O_RECURSIVE ;
  blob[0].deadline = *deadline ;
  blob[0].parsefunc = &s6dns_message_parse_answer_aaaa ;
  blob[0].data = &sa[0] ;
  blob[1].q = blob[0].q ;
  blob[1].qtype = S6DNS_T_A ;
  blob[1].options = S6DNS_O_RECURSIVE ;
  blob[1].deadline = *deadline ;
  blob[1].parsefunc = &s6dns_message_parse_answer_a ;
  blob[1].data = &sa[1] ;
  if (!s6dns_resolven_parse_r(blob, 2, servers, dbh, deadline, stamp)) return -1 ;
  if (!sa[0].len && !sa[1].len)
  {
    errno = blob[1].status ? blob[1].status : blob[0].status ;
    return 0 ;
  }
  if (!genalloc_readyplus(ip46full_t, ips, (sa[0].len >> 4) + (sa[1].len >> 2)))
  {
    stralloc_free(&sa[0]) ;
    stralloc_free(&sa[1]) ;
    return -1 ;
  }
  {
    int e = (!!sa[0].len << 1) | !!sa[1].len ;
    size_t n = genalloc_len(ip46full_t, ips) ;
    size_t i = 0 ;
    for (; i < (sa[0].len >> 4) ; i++)
      ip46full_from_ip6(genalloc_s(ip46full_t, ips) + n + i, sa[0].s + (i << 4)) ;
    n += i ;
    for (i = 0 ; i < (sa[1].len >> 2) ; i++)
      ip46full_from_ip4(genalloc_s(ip46full_t, ips) + n + i, sa[1].s + (i << 2)) ;
    n += i ;
    genalloc_setlen(ip46full_t, ips, n) ;
    stralloc_free(&sa[0]) ;
    stralloc_free(&sa[1]) ;
    return e ;
  }
}
