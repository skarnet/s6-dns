/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>

#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_init (s6dns_message_header_t *h, s6dns_message_counts_t *counts, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  if (packetlen < 12) return (errno = EPROTO, 0) ;
  s6dns_message_header_unpack(packet, h) ;
  *counts = h->counts ;
  *pos = 12 ;
  return 1 ;
}
