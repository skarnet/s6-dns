/* ISC license. */

#include <s6-dns/s6dns-message.h>
#include "s6dns-message-internal.h"

unsigned int s6dns_message_parse_skipqd (s6dns_message_counts_t *counts, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  for (;;)
  {
    register unsigned int r = s6dns_message_counts_next(counts) ;
    if (r != 1) return r ;
    if (!s6dns_message_get_domain_internal(0, 255, packet, packetlen, pos)) return 0 ;
    *pos += 4 ;
  }
}
