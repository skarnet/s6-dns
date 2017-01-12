/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/bytestr.h>
#include "s6dns-message-internal.h"

int s6dns_message_get_string_internal (char *s, size_t max, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  register unsigned char len = ((unsigned char const *)packet)[*pos] ;
  if (*pos + len + 1 > packetlen) return (errno = EPROTO, -1) ;
  if (len > max) return (errno = ENAMETOOLONG, -1) ;
  byte_copy(s, len, packet + *pos + 1) ;
  *pos += len + 1 ;
  return (int)len ;
}
