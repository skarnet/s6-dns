/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>
#include <s6-dns/s6dns-analyze.h>

int s6dns_analyze_record_domain (genwrite_t *gp, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int start)
{
  s6dns_domain_t d ;
  size_t len ;
  unsigned int pos = start ;
  char buf[S6DNS_FMT_DOMAIN] ;
  if (!s6dns_message_get_domain(&d, packet, packetlen, &pos)) return 0 ;
  if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
  len = s6dns_fmt_domain(buf, 256, &d) ;
  if (!len) return 0 ;
  if ((*gp->put)(gp->target, buf, len) < 0) return 0 ;
  return 1 ;
}
