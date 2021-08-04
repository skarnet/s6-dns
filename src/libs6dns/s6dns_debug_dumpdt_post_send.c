/* ISC license */

#include <sys/types.h>
#include <stdint.h>
#include <skalibs/uint16.h>
#include <skalibs/genwrite.h>
#include <skalibs/djbtime.h>
#include <s6-dns/s6dns-debug.h>

int s6dns_debug_dumpdt_post_send (s6dns_engine_t const *dt, void *data)
{
  genwrite *gp = data ;
  size_t len ;
  char buf[LOCALTMN_FMT] ;
  if ((*gp->put)(gp->target, "Sent query ", 11) < 11) return 0 ;
  {
    uint16_t id ;
    uint16_unpack_big(dt->sa.s + 2, &id) ;
    len = uint16_fmt(buf, id) ;
  }
  if ((*gp->put)(gp->target, buf, len) < (ssize_t)len) return 0 ;
  if ((*gp->put)(gp->target, " - next recv deadline is ", 25) < 25) return 0 ;
  {
    localtmn l ;
    if (!localtmn_from_tain(&l, &dt->localdeadline, 0)) return 0 ;
    len = localtmn_fmt(buf, &l) ;
  }
  if ((*gp->put)(gp->target, buf, len) < (ssize_t)len) return 0 ;
  if ((*gp->put)(gp->target, "\n\n", 2) < 2) return 0 ;
  return (*gp->flush)(gp->target) ;
}
