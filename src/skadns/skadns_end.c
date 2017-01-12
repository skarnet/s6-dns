/* ISC license. */

#include <stdint.h>
#include <skalibs/alloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/skaclient.h>
#include <s6-dns/skadns.h>

static int skadnsanswer_free (char *p, void *stuff)
{
  register skadnsanswer_t *q = (skadnsanswer_t_ref)p ;
  alloc_free(&q->data) ;
  (void)stuff ;
  return 1 ;
}

void skadns_end (skadns_t *a)
{
  skaclient_end(&a->connection) ;
  genalloc_free(uint16_t, &a->list) ;
  gensetdyn_iter(&a->q, &skadnsanswer_free, 0) ;
  gensetdyn_free(&a->q) ;
  *a = skadns_zero ;
}
