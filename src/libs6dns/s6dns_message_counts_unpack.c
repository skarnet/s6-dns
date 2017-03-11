/* ISC license. */

#include <skalibs/types.h>
#include <s6-dns/s6dns-message.h>

void s6dns_message_counts_unpack (char const *s, s6dns_message_counts_t *counts)
{
  uint16_unpack_big(s, &counts->qd) ;
  uint16_unpack_big(s+2, &counts->an) ;
  uint16_unpack_big(s+4, &counts->ns) ;
  uint16_unpack_big(s+6, &counts->nr) ;
}
