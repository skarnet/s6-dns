/* ISC license. */

#include <skalibs/posixplz.h>
#include <skalibs/textclient.h>

#include <s6-dns/skadns.h>

int skadns_startf (skadns_t *a, tain const *deadline, tain *stamp)
{
  static char const *const cargv[2] = { SKADNSD_PROG, 0 } ;
  return textclient_startf(&a->connection, cargv, (char const *const *)environ, TEXTCLIENT_OPTION_WAITPID, SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, deadline, stamp) ;
}
