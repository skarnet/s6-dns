/* ISC license. */

#include <skalibs/stralloc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_answer_aaaa (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  if ((section == 2) && (rr->rtype == S6DNS_T_AAAA) && (rr->rdlength == 16))
  {
    stralloc *data = stuff ;
    if (!stralloc_catb(data, packet + pos, 16)) return -1 ;
  }
  (void)packetlen ;
  return 1 ;
}
