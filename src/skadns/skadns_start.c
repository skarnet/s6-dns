/* ISC license. */

#include <skalibs/skaclient.h>
#include <s6-dns/skadns.h>

int skadns_start (skadns_t *a, char const *path, tain_t const *deadline, tain_t *stamp)
{
  return skaclient_start_b(&a->connection, &a->buffers, path, 0, SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, deadline, stamp) ;
}
