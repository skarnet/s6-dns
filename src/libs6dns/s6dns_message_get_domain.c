/* ISC license. */

#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_get_domain (s6dns_domain_t *d, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  return s6dns_message_get_domain_nodecode(d->s, 255, packet, packetlen, pos)
      && s6dns_domain_decode(d) ;
}
