/* ISC license. */

#include <errno.h>

#include <skalibs/error.h>

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolveq_r (char const *name, size_t len, uint16_t qtype, s6dns_message_rr_func_t_ref parsefunc, void *data, s6dns_rci_t const *rci, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  s6dns_engine_t dtl[rci->rulesnum] ;
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
      dtl[i] = s6dns_engine_zero ;
      if (!s6dns_engine_init_r(dtl + i, &rci->servers, S6DNS_O_RECURSIVE, domains[i].s, domains[i].len, qtype, dbh, deadline, stamp))
      {
        s6dns_engine_freen(dtl, i) ;
        return -1 ;
      }
    }
  }

 /*
    Wait until the "best" answer arrives, then scan until a positive answer
    is found.
    
    dtl[i].status == EAGAIN : query still pending
    other nonzero dtl[i].status : error, give up
    dtl[i].status == 0 : answer #i has arrived, in which case parse it;
      r < 0 : error, give up
      r > 0 : positive answer, return it
      r == 0 : negative answer. If it's non-fatal (i.e. NXDOMAIN),
       then move on to the next best FQDN.
 */

  for (;;)
  {
    int k = s6dns_resolven_loop(dtl, n, 1, deadline, stamp) ;
    if (k < 0) goto err ;
    if ((unsigned int)k == best)
    {
      for (;; best++)
      {
        s6dns_message_header_t h ;
        int r ;
        if (best >= n) goto notfound ;
        if (error_isagain(dtl[best].status)) break ;
        if (dtl[best].status) { errno = dtl[best].status ; goto err ; }
        r = s6dns_message_parse(&h, s6dns_engine_packet(dtl + best), s6dns_engine_packetlen(dtl + best), parsefunc, data) ;
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
  s6dns_engine_freen(dtl, n) ;
  return 1 ;

 notfound:
  s6dns_engine_freen(dtl, n) ;
  return (errno = e, 0) ;

 err:
  s6dns_engine_freen(dtl, n) ;
  return -1 ;
}
