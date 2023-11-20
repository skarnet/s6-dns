/* ISC license. */

#include <errno.h>

#include <skalibs/gensetdyn.h>

#include <s6-dns/skadns.h>

int skadns_packetlen (skadns_t const *a, uint16_t id)
{
  skadnsanswer_t *p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  switch (p->status)
  {
    case 0 : return p->len ;
    default : return (errno = p->status, -1) ;
  }
}
