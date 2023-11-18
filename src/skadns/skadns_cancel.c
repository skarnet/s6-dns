/* ISC license. */

#include <skalibs/bsdsnowflake.h>

#include <errno.h>

#include <skalibs/uint16.h>
#include <skalibs/error.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/textclient.h>

#include <s6-dns/skadns.h>

int skadns_cancel (skadns_t *a, uint16_t id, tain const *deadline, tain *stamp)
{
  int e = errno ;
  char pack[3] = "--q" ;
  skadnsanswer_t *p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  if (!error_isagain(p->status)) return skadns_release(a, id) ;
  uint16_pack_big(pack, id) ;
  if (textclient_command(&a->connection, pack, 3, deadline, stamp))
    return gensetdyn_delete(&a->q, id) ;
  if (errno != ENOENT) return 0 ;
  p->status = ECANCELED ;
  errno = e ;
  return 1 ;
}
