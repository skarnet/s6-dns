/* ISC license. */

#include <skalibs/genalloc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_answer_caa (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  if ((section == 2) && (rr->rtype == S6DNS_T_CAA))
  {
    genalloc *data = stuff ;
    s6dns_message_rr_caa_t caa ;
    if (!s6dns_message_get_caa(&caa, packet, packetlen, &pos, rr->rdlength)) return 0 ;
    if (!genalloc_append(s6dns_message_rr_caa_t, data, &caa)) return -1 ;
  }
  return 1 ;
}
