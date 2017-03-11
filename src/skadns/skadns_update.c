/* ISC license. */

/* Hey, OpenBSD, are you aware ECANCELED is POSIX? */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/types.h>
#include <skalibs/alloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/unixmessage.h>
#include <skalibs/skaclient.h>
#include <s6-dns/skadns.h>

static int msghandler (unixmessage_t const *m, void *context)
{
  skadns_t *a = (skadns_t *)context ;
  skadnsanswer_t *p ;
  uint16_t id ;
  if (m->len < 3 || m->nfds) return (errno = EPROTO, 0) ;
  uint16_unpack_big(m->s, &id) ;
  p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  if (p->status == ECANCELED)
  {
    p->status = EINVAL ;
    return gensetdyn_delete(&a->q, id) ;
  }
  if (!error_isagain(p->status)) return (errno = EINVAL, 0) ;
  if (!genalloc_readyplus(uint16_t, &a->list, 1)) return 0 ;
  if (!m->s[2])
  {
    p->data = alloc(m->len-3) ;
    if (!p->data) return 0 ;
    memcpy(p->data, m->s+3, m->len-3) ;
    p->len = m->len-3 ;
  }
  p->status = m->s[2] ;
  genalloc_append(uint16_t, &a->list, &id) ;
  return 1 ;
}

int skadns_update (skadns_t *a)
{
  genalloc_setlen(uint16_t, &a->list, 0) ;
  return skaclient_update(&a->connection, &msghandler, a) ;
}
