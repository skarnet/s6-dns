/* ISC license. */

#include <errno.h>
#include <skalibs/uint16.h>
#include <skalibs/bytestr.h>
#include <skalibs/siovec.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/skaclient.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/skadns.h>

static skadnsanswer_t const skadnsanswer_initial = { .status = EAGAIN, .data = 0, .len = 0 } ;

int skadns_send (skadns_t *a, uint16 *u, s6dns_domain_t const *d, uint16 qtype, tain_t const *limit, tain_t const *deadline, tain_t *stamp)
{
  unsigned int i ;
  char tmp[17] = "--Q" ;
  char err ;
  siovec_t v[2] = { { .s = tmp, .len = 17 }, { .s = (char *)d->s, .len = d->len } } ;
  if (!gensetdyn_new(&a->q, &i)) return 0 ;
  uint16_pack_big(tmp, (uint16)i) ;
  uint16_pack_big(tmp + 3, qtype) ;
  if (limit) tain_pack(tmp + 5, limit) ; else byte_zero(tmp + 5, 12) ;
  if (!skaclient_sendv(&a->connection, v, 2, &skaclient_default_cb, &err, deadline, stamp))
  {
    register int e = errno ;
    gensetdyn_delete(&a->q, i) ;
    errno = e ;
    return 0 ;
  }
  if (err)
  {
    gensetdyn_delete(&a->q, i) ;
    return (errno = err, 0) ;
  }
  *GENSETDYN_P(skadnsanswer_t, &a->q, i) = skadnsanswer_initial ;
  *u = i ;
  return 1 ;
}
