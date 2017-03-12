/* ISC license */

/* For EOVERFLOW in OpenBSD */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/fmtscan.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>
#include <skalibs/genwrite.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-ip46.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-analyze.h>
#include <s6-dns/s6dns-debug.h>

#ifdef SKALIBS_IPV6_ENABLED
# define s6dns_ipfmt(buf, ip, is6) ((is6) ? ip6_fmt(buf, ip) : ip4_fmt(buf, ip))
#else
# define s6dns_ipfmt(buf, ip, is6) ip4_fmt(buf, ip)
#endif

int s6dns_debug_dumpdt_pre_send (s6dns_engine_t const *dt, void *data)
{
  genwrite_t *gp = data ;
  size_t len ;
  char buf[LOCALTMN_FMT] ;
  if ((*gp->put)(gp->target, "Preparing to send via ", 22) < 22) return 0 ;
  if ((*gp->put)(gp->target, dt->flagtcp ? "TCP" : "UDP", 3) < 3) return 0 ;
  if ((*gp->put)(gp->target, " to ", 4) < 4) return 0 ;
  len = dt->sa.s[4] & 1 ;
  if ((*gp->put)(gp->target, len ? "cache" : "server", len ? 5 : 6) < (len ? 5 : 6)) return 0 ;
  if ((*gp->put)(gp->target, " ", 1) < 1) return 0 ;
  len = s6dns_ipfmt(buf, s6dns_ip46list_ip(&dt->servers, dt->curserver), s6dns_ip46list_is6(&dt->servers, dt->curserver)) ;
  if ((*gp->put)(gp->target, buf, len) < (ssize_t)len) return 0 ;
  if ((*gp->put)(gp->target, " with deadline ", 15) < 15) return 0 ;
  {
    localtmn_t l ;
    if (!localtmn_from_tain(&l, &dt->localdeadline, 0))
    {
      if (errno != EOVERFLOW) return 0 ;
      memcpy(buf, "\"infinite\"", 10) ; len = 10 ;
    }
    else len = localtmn_fmt(buf, &l) ;
  }
  if ((*gp->put)(gp->target, buf, len) < (ssize_t)len) return 0 ;
  if ((*gp->put)(gp->target, ", ", 2) < 2) return 0 ;
  if (dt->flagstrict && (*gp->put)(gp->target, "strict, ", 8) < 8) return 0 ;
  if ((*gp->put)(gp->target, "query id ", 9) < 9) return 0 ;
  {
    uint16_t id ;
    uint16_unpack_big(dt->sa.s + 2, &id) ;
    len = uint16_fmt(buf, id) ;
  }
  if ((*gp->put)(gp->target, buf, len) < (ssize_t)len) return 0 ;
  if ((*gp->put)(gp->target, ":\n", 2) < 2) return 0 ;
  if (!s6dns_analyze_packet(gp, dt->sa.s + 2, dt->querylen - 2, 1)) return 0 ;
  if ((*gp->put)(gp->target, "\n", 1) < 1) return 0 ;
  return (*gp->flush)(gp->target) ;
}
