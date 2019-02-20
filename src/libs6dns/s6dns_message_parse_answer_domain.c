/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/genalloc.h>

#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_answer_domain (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  s6dns_dpag_t *data = stuff ;
  if ((section == 2) && (rr->rtype == data->rtype))
  {
    s6dns_domain_t d ;
    unsigned int start = pos ;
    if (!s6dns_message_get_domain(&d, packet, packetlen, &pos)) return 0 ;
    if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
    if (!genalloc_append(s6dns_domain_t, &data->ds, &d)) return -1 ;
  }
  return 1 ;
}
