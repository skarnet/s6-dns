/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <skalibs/types.h>
#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-analyze.h>

static s6dns_analyze_rtypetable_t const *rtypelookup (uint16_t rtype)
{
  s6dns_analyze_rtypetable_t const *wut = s6dns_analyze_rtypetable ;
  while (wut->rtype && wut->rtype != rtype) wut++ ;
  return wut ;
}

int s6dns_analyze_record (genwrite_t *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos)
{
  s6dns_analyze_rtypetable_t const *wut = rtypelookup(rr->rtype) ;
  {
    char buf[256] ;
    unsigned int n = s6dns_domain_tostring(buf, 256, &rr->name) ;
    if (!n) return 0 ;
    if ((*gp->put)(gp->target, buf, n) < 0) return 0 ;
  }
  {
    char fmt[UINT32_FMT+1] = " " ;
    if ((*gp->put)(gp->target, fmt, 1 + uint32_fmt(fmt+1, rr->ttl)) < 0) return 0 ;
  }
  if ((*gp->put)(gp->target, " ", 1) < 0) return 0 ;
  if ((*gp->put)(gp->target, wut->string, strlen(wut->string)) < 0) return 0 ;
  if ((*gp->put)(gp->target, " ", 1) < 0) return 0 ;
  if (!(*wut->f)(gp, rr, packet, packetlen, pos)) return 0 ;
  if ((*gp->put)(gp->target, "\n", 1) < 0) return 0 ;
  return 1 ;
}
