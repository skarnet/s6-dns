 /* ISC license. */

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolvenoq_r (char const *name, size_t len, uint16_t qtype, s6dns_message_rr_func_ref parsefunc, void *data, s6dns_engine_t *dt, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain const *deadline, tain *stamp)
{
  s6dns_domain_t d ;
  if (!s6dns_domain_fromstring_noqualify_encode(&d, name, len)) return -1 ;
  return s6dns_resolve_parse_r(&d, qtype, parsefunc, data, dt, servers, dbh, deadline, stamp) ;
}
