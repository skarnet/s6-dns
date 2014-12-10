/* ISC license. */

#include <skalibs/uint16.h>
#include <s6-dns/s6dns-message.h>

void s6dns_message_counts_pack (char *s, s6dns_message_counts_t const *counts)
{
  uint16_pack_big(s, counts->qd) ;
  uint16_pack_big(s+2, counts->an) ;
  uint16_pack_big(s+4, counts->ns) ;
  uint16_pack_big(s+6, counts->nr) ;
}
