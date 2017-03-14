/* ISC license. */

#include <s6-dns/s6dns-message.h>
#include "s6dns-message-internal.h"

int s6dns_message_get_string (s6dns_domain_t *d, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  int r = s6dns_message_get_string_internal(d->s, 255, packet, packetlen, pos) ;
  if (r < 0) return 0 ;
  d->len = r ;
  return 1 ;
}
