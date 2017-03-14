/* ISC license. */

#include <skalibs/environ.h>
#include <skalibs/skaclient.h>
#include <s6-dns/skadns.h>

int skadns_startf (skadns_t *a, tain_t const *deadline, tain_t *stamp)
{
  static char const *const cargv[2] = { SKADNSD_PROG, 0 } ;
  return skaclient_startf_b(&a->connection, &a->buffers, cargv[0], cargv, (char const *const *)environ, SKACLIENT_OPTION_WAITPID, SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, deadline, stamp) ;
}
