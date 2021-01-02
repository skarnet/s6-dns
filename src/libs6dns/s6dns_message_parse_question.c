/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/uint16.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_question (s6dns_message_counts_t *counts, s6dns_domain_t *name, uint16_t *qtypep, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  s6dns_domain_t d ;
  uint16_t qtype ;
  uint16_t qclass ;
  if (!counts->qd) return (errno = EINVAL, 0) ;
  if (!s6dns_message_get_domain(&d, packet, packetlen, pos)) return 0 ;
  if (*pos + 4 > packetlen) return (errno = EPROTO, 0) ;
  uint16_unpack_big(packet + *pos, &qtype) ; *pos += 2 ;
  uint16_unpack_big(packet + *pos, &qclass) ; *pos += 2 ;
  if (qclass != S6DNS_C_IN) return (errno = ENOTSUP, 0) ;
  counts->qd-- ;
  *name = d ;
  *qtypep = qtype ;
  return 1 ;
}
