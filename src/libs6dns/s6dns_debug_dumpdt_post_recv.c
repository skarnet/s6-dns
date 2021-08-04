/* ISC license */

#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-debug.h>

int s6dns_debug_dumpdt_post_recv (s6dns_engine_t const *dt, void *data)
{
  genwrite *gp = data ;
  (void)dt ;
  if ((*gp->put)(gp->target, "Received a packet\n", 19) < 19) return 0 ;
  if ((*gp->put)(gp->target, "\n", 1) < 1) return 0 ;
  return (*gp->flush)(gp->target) ;
}
