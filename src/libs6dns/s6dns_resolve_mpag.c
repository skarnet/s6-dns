/* ISC license. */

#include <s6-dns/s6dns-resolve.h>

int s6dns_resolve_mpag_r (stralloc *sa, genalloc *offsets, char const *name, unsigned int len, uint16_t qtype, s6dns_message_rr_func_ref parsefunc, int qualif, s6dns_engine_t *dt, s6dns_rci_t const *rci, s6dns_debughook_t const *dbh, tain const *deadline, tain *stamp)
{
  s6dns_mpag_t data ;
  int r ;
  data.sa = *sa ;
  data.offsets = *offsets ;
  data.rtype = qtype ;
  r = s6dns_resolve_r(name, len, qtype, parsefunc, &data, qualif, dt, rci, dbh, deadline, stamp) ;
  *sa = data.sa ;
  *offsets = data.offsets ;
  return r ;
}
