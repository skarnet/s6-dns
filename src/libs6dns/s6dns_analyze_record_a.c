/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/genwrite.h>
#include <skalibs/fmtscan.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-analyze.h>

int s6dns_analyze_record_a (genwrite_t *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos)
{
  char fmt[IP4_FMT] ;
  if (rr->rdlength != 4) return (errno = EPROTO, 0) ;
  if (pos + 4 > packetlen) return (errno = EPROTO, 0) ;
  if ((*gp->put)(gp->target, fmt, ip4_fmt(fmt, packet + pos)) < 0) return 0 ;
  return 1 ;
}
