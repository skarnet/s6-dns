/* ISC license. */

#include <stdint.h>
#include <errno.h>
#include <skalibs/tai.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-ip46.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

int s6dns_resolve_core_r (s6dns_domain_t const *d, uint16_t qtype, s6dns_engine_t *dt, s6dns_ip46list_t const *servers, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t *stamp)
{
  if (!s6dns_engine_init_r(dt, servers, S6DNS_O_RECURSIVE, d->s, d->len, qtype, dbh, deadline, stamp)) return 0 ;
  if (!s6dns_resolve_loop_r(dt, deadline, stamp))
  {
    s6dns_engine_recycle(dt) ;
    return 0 ;
  }
  return 1 ;
}
