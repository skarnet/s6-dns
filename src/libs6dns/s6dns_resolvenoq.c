 /* ISC license. */

#include <skalibs/uint16.h>
#include <skalibs/tai.h>
#include <s6-dns/s6dns-ip46.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolvenoq_r (char const *name, unsigned int len, uint16 qtype, s6dns_message_rr_func_t_ref parsefunc, void *data, s6dns_engine_t *dt, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  s6dns_domain_t d ;
  if (!s6dns_domain_fromstring_noqualify_encode(&d, name, len)) return -1 ;
  return s6dns_resolve_parse_r(&d, qtype, parsefunc, data, dt, servers, dbh, deadline, stamp) ;
}
