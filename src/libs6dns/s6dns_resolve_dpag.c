/* ISC license. */

#include <s6-dns/s6dns-resolve.h>

int s6dns_resolve_dpag_r (genalloc *ds, char const *name, unsigned int len, uint16_t qtype, int qualif, s6dns_engine_t *dt, s6dns_rci_t const *rci, s6dns_debughook_t const *dbh, tain const *deadline, tain *stamp)
{
  s6dns_dpag_t data ;
  int r ;
  data.ds = *ds ;
  data.rtype = qtype ;
  r = s6dns_resolve_r(name, len, qtype, &s6dns_message_parse_answer_domain, &data, qualif, dt, rci, dbh, deadline, stamp) ;
  *ds = data.ds ;
  return r ;
}
