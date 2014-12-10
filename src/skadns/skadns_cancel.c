/* ISC license. */

/* OpenBSD sucks */
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <errno.h>
#include <skalibs/uint16.h>
#include <skalibs/error.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/skaclient.h>
#include <s6-dns/skadns.h>

int skadns_cancel (skadns_t *a, uint16 id, tain_t const *deadline, tain_t *stamp)
{
  char pack[3] = "--q" ;
  char err ;
  register skadnsanswer_t *p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  if (!error_isagain(p->status)) return skadns_release(a, id) ;
  uint16_pack_big(pack, id) ;
  if (!skaclient_send(&a->connection, pack, 3, &skaclient_default_cb, &err, deadline, stamp)) return 0 ;
  if (!err) return gensetdyn_delete(&a->q, id) ;
  if (err != ENOENT) return (errno = err, 0) ;
  p->status = ECANCELED ;
  return 1 ;
}
