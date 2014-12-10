/* ISC license. */

#include <s6-dns/s6dns-message.h>

int s6dns_message_get_hinfo (s6dns_message_rr_hinfo_t_ref hinfo, char const *packet, unsigned int packetlen, unsigned int *pos)
{
  return s6dns_message_get_string(&hinfo->cpu, packet, packetlen, pos)
   && s6dns_message_get_string(&hinfo->os, packet, packetlen, pos) ;
}
