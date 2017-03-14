/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/uint16.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_get_srv (s6dns_message_rr_srv_t *srv, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  if (*pos + 7 > packetlen) return (errno = EPROTO, 0) ;
  uint16_unpack_big(packet + *pos, &srv->priority) ; *pos += 2 ;
  uint16_unpack_big(packet + *pos, &srv->weight) ; *pos += 2 ;
  uint16_unpack_big(packet + *pos, &srv->port) ; *pos += 2 ;
  return s6dns_message_get_domain(&srv->target, packet, packetlen, pos) ;
}
