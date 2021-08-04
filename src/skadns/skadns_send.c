/* ISC license. */

#include <sys/uio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/uint16.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/textclient.h>
#include <s6-dns/skadns.h>


int skadns_send (skadns_t *a, uint16_t *u, s6dns_domain_t const *d, uint16_t qtype, tain const *limit, tain const *deadline, tain *stamp)
{
  static skadnsanswer_t const skadnsanswer_initial = { .status = EAGAIN, .data = 0, .len = 0 } ;
  uint32_t i ;
  char tmp[17] = "--Q" ;
  struct iovec v[2] = { { .iov_base = tmp, .iov_len = 17 }, { .iov_base = (void *)d->s, .iov_len = d->len } } ;
  if (!gensetdyn_new(&a->q, &i)) return 0 ;
  if (i > UINT16_MAX)
  {
    gensetdyn_delete(&a->q, i) ;
    return (errno = EMFILE, 0) ;
  }
  uint16_pack_big(tmp, (uint16_t)i) ;
  uint16_pack_big(tmp + 3, qtype) ;
  if (limit) tain_pack(tmp + 5, limit) ; else memset(tmp + 5, 0, 12) ;
  if (!textclient_commandv(&a->connection, v, 2, deadline, stamp))
  {
    int e = errno ;
    gensetdyn_delete(&a->q, i) ;
    errno = e ;
    return 0 ;
  }
  *GENSETDYN_P(skadnsanswer_t, &a->q, i) = skadnsanswer_initial ;
  *u = i ;
  return 1 ;
}
