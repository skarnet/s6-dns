/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/posixishard.h>

#include <s6-dns/s6dns-message.h>

int s6dns_message_get_caa (s6dns_message_rr_caa_t *caa, char const *packet, unsigned int packetlen, unsigned int *pos, uint16_t rdlength)
{
  unsigned char taglen ;
  if (rdlength < 4) return (errno = EPROTO, 0) ;
  if (*pos + rdlength > packetlen) return (errno = EPROTO, 0) ;
  caa->flags = packet[(*pos)++] ;
  taglen = packet[(*pos)++] ;
  if (rdlength < taglen + 3 || rdlength > taglen + 257) return (errno = EPROTO, 0) ;
  memcpy(caa->tag, packet + *pos, taglen) ;
  caa->tag[taglen] = 0 ;
  *pos += taglen ;
  memcpy(caa->value, packet + *pos, rdlength - taglen - 2) ;
  caa->value[rdlength - taglen - 1] = 0 ;
  *pos += rdlength - taglen - 2 ;
  return 1 ;
}
