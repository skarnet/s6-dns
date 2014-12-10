/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>
#include <s6-dns/s6dns-analyze.h>

int s6dns_analyze_record_mx (genwrite_t *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int start)
{
  s6dns_message_rr_mx_t mx ;
  char buf[S6DNS_FMT_MX] ;
  unsigned int pos = start ;
  unsigned int len ;
  if (!s6dns_message_get_mx(&mx, packet, packetlen, &pos)) return 0 ;
  if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
  len = s6dns_fmt_mx(buf, S6DNS_FMT_MX, &mx) ;
  if (!len) return 0 ;
  if ((*gp->put)(gp->target, buf, len) < 0) return 0 ;
  return 1 ;
}
