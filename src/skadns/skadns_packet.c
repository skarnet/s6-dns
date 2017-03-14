/* ISC license. */

#include <errno.h>
#include <skalibs/gensetdyn.h>
#include <s6-dns/skadns.h>

char const *skadns_packet (skadns_t const *a, uint16_t id)
{
  skadnsanswer_t *p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  switch (p->status)
  {
    case 0 : return (char const *)p->data ;
    default : return (errno = p->status, (char const *)0) ;
  }
}
