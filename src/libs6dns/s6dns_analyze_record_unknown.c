/* ISC license. */

#include <stdint.h>
#include <skalibs/uint16.h>
#include <skalibs/fmtscan.h>
#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-analyze.h>

int s6dns_analyze_record_unknown (genwrite_t *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos)
{
  char fmt[UINT16_FMT] ;
  if ((*gp->put)(gp->target, "rtype ", 6) < 0) return 0 ;
  if ((*gp->put)(gp->target, fmt, uint16_fmt(fmt, rr->rtype)) < 0) return 0 ;
  if ((*gp->put)(gp->target, " length ", 8) < 0) return 0 ;
  if ((*gp->put)(gp->target, fmt, uint16_fmt(fmt, rr->rdlength)) < 0) return 0 ;
  if ((*gp->put)(gp->target, ": ", 2) < 0) return 0 ;
  {
    register uint16_t i = 0 ;
    for (; i < rr->rdlength ; i++)
      if ((*gp->put)(gp->target, fmt, ucharn_fmt(fmt, packet + pos + i, 1)) < 0)
        return 0 ;
  }
  (void)packetlen ;
  return 1 ;
}
