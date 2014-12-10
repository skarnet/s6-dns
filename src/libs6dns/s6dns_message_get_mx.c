/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/uint16.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_get_mx (s6dns_message_rr_mx_t *mx, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  if (*pos + 3 > packetlen) return (errno = EPROTO, 0) ;
  uint16_unpack_big(packet + *pos, &mx->preference) ; *pos += 2 ;
  return s6dns_message_get_domain(&mx->exchange, packet, packetlen, pos) ;
}
