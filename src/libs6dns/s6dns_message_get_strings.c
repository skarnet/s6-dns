/* ISC license. */

#include <s6-dns/s6dns-message.h>
#include "s6dns-message-internal.h"

int s6dns_message_get_strings (char *s, unsigned int rdlength, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  unsigned int max = rdlength, len = 0 ;
  while (rdlength)
  {
    unsigned int start = *pos ;
    int r = s6dns_message_get_string_internal(s + len, max - len, packet, packetlen, pos) ;
    if (r < 0) return -1 ;
    len += r ; rdlength -= *pos - start ;
  }
  return len ;
}
