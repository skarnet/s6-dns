/* ISC license. */

#include <skalibs/textclient.h>
#include <s6-dns/skadns.h>

int skadns_start (skadns_t *a, char const *path, tain_t const *deadline, tain_t *stamp)
{
  return textclient_start(&a->connection, path, 0, SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, deadline, stamp) ;
}
