/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/error.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>
#include <s6-dns/s6dns-analyze.h>

int s6dns_analyze_record_caa (genwrite_t *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int start)
{
  s6dns_message_rr_caa_t caa ;
  size_t len ;
  unsigned int pos = start ;
  char buf[S6DNS_FMT_CAA] ;
  if (!s6dns_message_get_caa(&caa, packet, packetlen, &pos, rr->rdlength)) return 0 ;
  if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
  len = s6dns_fmt_caa(buf, S6DNS_FMT_CAA, &caa) ;
  if (!len) return 0 ;
  if ((*gp->put)(gp->target, buf, len) < 0) return 0 ;
  return 1 ;
}
