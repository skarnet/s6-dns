/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/stralloc.h>
#include <skalibs/skamisc.h>

#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-analyze.h>

int s6dns_analyze_record_strings (genwrite *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int start)
{
  stralloc sa = STRALLOC_ZERO ;
  char buf[rr->rdlength] ;
  unsigned int pos = start ;
  int r = s6dns_message_get_strings(buf, rr->rdlength, packet, packetlen, &pos) ;
  if (r < 0) return 0 ;
  if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
  if (!string_quote(&sa, buf, r)) return 0 ;
  r = (*gp->put)(gp->target, sa.s, sa.len) >= 0 ;
  stralloc_free(&sa) ;
  return r ;
}
