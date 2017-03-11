/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/genalloc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_answer_hinfo (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  if ((section == 2) && (rr->rtype == S6DNS_T_HINFO))
  {
    genalloc *data = stuff ;
    s6dns_message_rr_hinfo_t hinfo ;
    unsigned int start = pos ;
    if (!s6dns_message_get_hinfo(&hinfo, packet, packetlen, &pos)) return 0 ;
    if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
    if (!genalloc_append(s6dns_message_rr_hinfo_t, data, &hinfo)) return -1 ;
  }
  return 1 ;
}
