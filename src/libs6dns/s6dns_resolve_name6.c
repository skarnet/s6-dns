/* ISC license. */

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolve_name6_r (genalloc *list, char const *ip, s6dns_engine_t *dt, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain const *deadline, tain *stamp)
{
  s6dns_dpag_t data ;
  s6dns_domain_t d ;
  int r ;
  s6dns_domain_arpafromip6(&d, ip, 128) ;
  s6dns_domain_encode(&d) ;
  data.ds = *list ;
  data.rtype = S6DNS_T_PTR ;
  r = s6dns_resolve_parse_r(&d, data.rtype, &s6dns_message_parse_answer_domain, &data, dt, servers, dbh, deadline, stamp) ;
  *list = data.ds ;
  return r ;
}
