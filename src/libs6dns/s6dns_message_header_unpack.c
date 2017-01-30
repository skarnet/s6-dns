/* ISC license. */

#include <skalibs/uint16.h>
#include <s6-dns/s6dns-message.h>

void s6dns_message_header_unpack (char const *s, s6dns_message_header_t *h)
{
  uint16_unpack_big(s, &h->id) ;
  h->qr = ((unsigned char *)s)[2] & 0x8000U ? 1 : 0 ;
  h->opcode = (s[2] >> 3) & 15 ;
  h->aa = s[2] & 4 ? 1 : 0 ;
  h->tc = s[2] & 2 ? 1 : 0 ;
  h->rd = s[2] & 1 ;
  h->ra = s[3] & 0x8000U ? 1 : 0 ;
  h->z = (s[3] >> 4) & 7 ;
  h->rcode = s[3] & 15 ;
  s6dns_message_counts_unpack(s+4, &h->counts) ;
}
