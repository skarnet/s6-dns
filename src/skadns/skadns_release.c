/* ISC license. */

/* OpenBSD sucks */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <stdint.h>
#include <errno.h>
#include <skalibs/alloc.h>
#include <skalibs/gensetdyn.h>
#include <s6-dns/skadns.h>

int skadns_release (skadns_t *a, uint16_t id)
{
  register skadnsanswer_t *p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  switch (p->status)
  {
    case 0 :
      alloc_free(p->data) ; p->data = 0 ; p->len = 0 ;
      break ;
    case EAGAIN :
    case ECANCELED :
      return (errno = EBUSY, 0) ;
    case EINVAL :
      return (errno = EINVAL, 0) ;
    default : break ;
  }
  p->status = EINVAL ;
  return gensetdyn_delete(&a->q, id) ;
}
