/* ISC license. */

#include <s6-dns/s6dns-message.h>

unsigned int s6dns_message_parse_skipqd (s6dns_message_counts_t *counts, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  for (;;)
  {
    unsigned int r = s6dns_message_counts_next(counts) ;
    if (r != 1) return r ;
    if (!s6dns_message_get_domain_nodecode(0, 255, packet, packetlen, pos)) return 0 ;
    *pos += 4 ;
  }
}
