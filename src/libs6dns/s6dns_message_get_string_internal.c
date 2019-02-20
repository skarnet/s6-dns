/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/posixishard.h>

#include "s6dns-message-internal.h"

int s6dns_message_get_string_internal (char *s, size_t max, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  unsigned char len = ((unsigned char const *)packet)[*pos] ;
  if (*pos + len + 1 > packetlen) return (errno = EPROTO, -1) ;
  if (len > max) return (errno = ENAMETOOLONG, -1) ;
  memcpy(s, packet + *pos + 1, len) ;
  *pos += len + 1 ;
  return len ;
}
