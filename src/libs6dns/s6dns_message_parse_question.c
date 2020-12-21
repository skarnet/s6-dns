/* ISC license. */

#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/uint16.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_question (s6dns_domain_t *name, uint16_t *qtype, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  uint16_t qclass ;
  if (!s6dns_message_get_domain(name, packet, packetlen, pos)) return 0 ;
  if (*pos + 4 > packetlen) return (errno = EPROTO, 0) ;
  uint16_unpack_big(packet + *pos, qtype) ; *pos += 2 ;
  uint16_unpack_big(packet + *pos, &qclass) ; *pos += 2 ;
  if (qclass != S6DNS_C_IN) return (errno = ENOTSUP, 0) ;
  return 1 ;
}
