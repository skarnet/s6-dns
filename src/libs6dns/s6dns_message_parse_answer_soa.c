/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/genalloc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_answer_soa (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  if ((section == 2) && (rr->rtype == S6DNS_T_SOA))
  {
    genalloc *data = stuff ;
    s6dns_message_rr_soa_t soa ;
    register unsigned int start = pos ;
    if (!s6dns_message_get_soa(&soa, packet, packetlen, &pos)) return 0 ;
    if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
    if (!genalloc_append(s6dns_message_rr_soa_t, data, &soa)) return -1 ;
  }
  return 1 ;
}
