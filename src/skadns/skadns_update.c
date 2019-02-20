/* ISC license. */

#include <skalibs/nonposix.h>

#include <sys/uio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/error.h>
#include <skalibs/uint16.h>
#include <skalibs/alloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/textclient.h>

#include <s6-dns/skadns.h>

static int msghandler (struct iovec const *v, void *context)
{
  skadns_t *a = (skadns_t *)context ;
  char const *s = v->iov_base ;
  skadnsanswer_t *p ;
  uint16_t id ;
  if (v->iov_len < 3) return (errno = EPROTO, 0) ;
  uint16_unpack_big(s, &id) ;
  p = GENSETDYN_P(skadnsanswer_t, &a->q, id) ;
  if (p->status == ECANCELED)
  {
    p->status = EINVAL ;
    return gensetdyn_delete(&a->q, id) ;
  }
  if (!error_isagain(p->status)) return (errno = EINVAL, 0) ;
  if (!genalloc_readyplus(uint16_t, &a->list, 1)) return 0 ;
  if (!s[2])
  {
    p->data = alloc(v->iov_len-3) ;
    if (!p->data) return 0 ;
    memcpy(p->data, s+3, v->iov_len-3) ;
    p->len = v->iov_len-3 ;
  }
  p->status = s[2] ;
  genalloc_append(uint16_t, &a->list, &id) ;
  return 1 ;
}

int skadns_update (skadns_t *a)
{
  genalloc_setlen(uint16_t, &a->list, 0) ;
  return textclient_update(&a->connection, &msghandler, a) ;
}
