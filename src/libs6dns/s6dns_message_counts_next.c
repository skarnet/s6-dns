/* ISC license. */

#include <s6-dns/s6dns-message.h>

unsigned int s6dns_message_counts_next (s6dns_message_counts_t *counts)
{
  if (counts->qd) { counts->qd-- ; return 1 ; }
  else if (counts->an) { counts->an-- ; return 2 ; }
  else if (counts->ns) { counts->ns-- ; return 3 ; }
  else if (counts->nr) { counts->nr-- ; return 4 ; }
  else return 0 ;
}
