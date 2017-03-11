/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/types.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_get_soa (s6dns_message_rr_soa_t *soa, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  if (!s6dns_message_get_domain(&soa->mname, packet, packetlen, pos)) return 0 ;
  if (!s6dns_message_get_domain(&soa->rname, packet, packetlen, pos)) return 0 ;
  if (*pos + 20 > packetlen) return (errno = EPROTO, 0) ;
  uint32_unpack_big(packet + *pos, &soa->serial) ; *pos += 4 ;
  uint32_unpack_big(packet + *pos, &soa->refresh) ; *pos += 4 ;
  uint32_unpack_big(packet + *pos, &soa->retry) ; *pos += 4 ;
  uint32_unpack_big(packet + *pos, &soa->expire) ; *pos += 4 ;
  uint32_unpack_big(packet + *pos, &soa->minimum) ; *pos += 4 ;
  return 1 ;
}
