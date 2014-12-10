/* ISC license. */

#include <skalibs/uint16.h>
#include <s6-dns/s6dns-message.h>

void s6dns_message_header_pack (char *s, s6dns_message_header_t const *h)
{
  uint16_pack_big(s, h->id) ;
  s[2] = (h->qr << 7) | (h->opcode << 3) | (h->aa << 2) | (h->tc << 1) | h->rd ;
  s[3] = (h->z << 4) | h->rcode ;
  s6dns_message_counts_pack(s+4, &h->counts) ;
}
