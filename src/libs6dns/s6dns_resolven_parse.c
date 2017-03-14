/* ISC license. */

#include <errno.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolven_parse_r (s6dns_resolve_t *list, unsigned int n, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  s6dns_engine_t dtl[n] ;
  unsigned int i = 0 ;
  for (; i < n ; i++) list[i].status = ECONNABORTED ;
  for (i = 0 ; i < n ; i++)
  {
    dtl[i] = s6dns_engine_zero ;
    if (!s6dns_engine_init_r(dtl + i, servers, list[i].options, list[i].q.s, list[i].q.len, list[i].qtype, dbh, &list[i].deadline, stamp))
    {
      list[i].status = errno ;
      s6dns_engine_freen(dtl, i) ;
      return 0 ;
    }
    list[i].status = EAGAIN ;
  }

  if (s6dns_resolven_loop(dtl, n, 0, deadline, stamp) < 0) goto err ;

  for (i = 0 ; i < n ; i++)
  {
    if (dtl[i].status) list[i].status = dtl[i].status ;
    else
    {
      s6dns_message_header_t h ;
      int r = s6dns_message_parse(&h, s6dns_engine_packet(dtl + i), s6dns_engine_packetlen(dtl + i), list[i].parsefunc, list[i].data) ;
      if (r < 0) goto err ;
      list[i].status = r ? 0 : errno ;
    }
  }
  s6dns_engine_freen(dtl, n) ;
  return 1 ;

 err:
  s6dns_engine_freen(dtl, n) ;
  return 0 ;
}
