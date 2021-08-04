/* ISC license. */

#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolve_parse_r (s6dns_domain_t const *d, uint16_t qtype, s6dns_message_rr_func_ref parsefunc, void *data, s6dns_engine_t *dt, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain const *deadline, tain *stamp)
{
  int r ;
  if (!s6dns_resolve_core_r(d, qtype, dt, servers, dbh, deadline, stamp)) return -1 ;
  {
    s6dns_message_header_t h ;
    r = s6dns_message_parse(&h, s6dns_engine_packet(dt), s6dns_engine_packetlen(dt), parsefunc, data) ;
  }
  s6dns_engine_recycle(dt) ;
  return r ;
}
