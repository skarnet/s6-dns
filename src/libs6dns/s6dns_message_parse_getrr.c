/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>

#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_getrr (s6dns_message_rr_t_ref rr, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  if (!s6dns_message_get_domain(&rr->name, packet, packetlen, pos)) return 0 ;
  if (*pos + 10 > packetlen) return (errno = EPROTO, 0) ;
  uint16_unpack_big(packet + *pos, &rr->rtype) ; *pos += 2 ;
  uint16_unpack_big(packet + *pos, &rr->rclass) ; *pos += 2 ;
  uint32_unpack_big(packet + *pos, &rr->ttl) ; *pos += 4 ;
  uint16_unpack_big(packet + *pos, &rr->rdlength) ; *pos += 2 ;
  if (*pos + rr->rdlength > packetlen) return (errno = EPROTO, 0) ;
  return 1 ;
}
