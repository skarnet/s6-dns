/* ISC license. */

#include <errno.h>
#include <s6-dns/s6dns-message.h>

unsigned int s6dns_message_parse_next (s6dns_message_counts_t *counts, s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  *pos += rr->rdlength ;
  (void)packet ; (void)packetlen ;
  return s6dns_message_counts_next(counts) ;
}
