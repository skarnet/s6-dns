/* ISC license. */

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_question (s6dns_message_counts_t *counts, s6dns_domain_t *name, uint16_t *qtypep, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  return s6dns_message_parse_question_nodecode(counts, name, qtypep, packet, packetlen, pos) && s6dns_domain_decode(name) ;
}
