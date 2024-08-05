/* ISC license. */

#ifndef S6DNS_ENGINE_H
#define S6DNS_ENGINE_H

#include <stdint.h>
#include <errno.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-ip46.h>


 /* The dt structure: all the DNS q/r state information, transport-agnostic */

typedef struct s6dns_engine_s s6dns_engine_t, *s6dns_engine_t_ref ;


 /* Debug function hooks */

typedef int s6dns_debughook_func (s6dns_engine_t const *, void *) ;
typedef s6dns_debughook_func *s6dns_debughook_func_ref ;

typedef struct s6dns_debughook_s s6dns_debughook_t, *s6dns_debughook_t_ref ;
struct s6dns_debughook_s
{
  s6dns_debughook_func_ref post_recv ;
  s6dns_debughook_func_ref pre_send ;
  s6dns_debughook_func_ref post_send ;
  void *external ;
} ;
#define S6DNS_DEBUGHOOK_ZERO { .post_recv = 0, .pre_send = 0, .post_send = 0, .external = 0 }
extern s6dns_debughook_t const s6dns_debughook_zero ;
      

 /*
   s6dns-engine: the asynchronous DNS resolution primitives.
 */

struct s6dns_engine_s
{
  stralloc sa ; /* 2 bytes (qlen) + qlen bytes (query) + answers */
  tain deadline ;
  tain localdeadline ;
  unsigned int querylen ;
  int fd ;
  uint32_t protostate ;
  s6dns_ip46list_t servers ;
  s6dns_debughook_t const *debughook ;
  unsigned int curserver ;
  int status ;
  unsigned int flagstrict : 1 ;
  unsigned int flagtcp : 1 ;
  unsigned int flagconnecting : 1 ;
  unsigned int flagreading : 1 ;
  unsigned int flagwriting : 1 ;
} ;

#define S6DNS_ENGINE_ZERO \
{ \
  .sa = STRALLOC_ZERO, \
  .deadline = TAIN_ZERO, \
  .localdeadline = TAIN_ZERO, \
  .querylen = 0, \
  .fd = -1, \
  .protostate = 0, \
  .servers = S6DNS_IP46LIST_ZERO, \
  .debughook = 0, \
  .curserver = 0, \
  .status = ECONNABORTED, \
  .flagstrict = 0, \
  .flagtcp = 0, \
  .flagconnecting = 0, \
  .flagreading = 0, \
  .flagwriting = 0 \
}

extern s6dns_engine_t const s6dns_engine_zero ;
extern s6dns_engine_t s6dns_engine_here ;

extern void s6dns_engine_recycle (s6dns_engine_t *) ;
extern void s6dns_engine_free (s6dns_engine_t *) ;
extern void s6dns_engine_freen (s6dns_engine_t *, unsigned int) ;

#define s6dns_engine_init(dt, servers, options, q, qlen, qtype, deadline, stamp) s6dns_engine_init_r(dt, servers, options, q, qlen, qtype, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_engine_init_g(dt, servers, options, q, qlen, qtype, deadline) s6dns_engine_init(dt, servers, options, q, qlen, qtype, (deadline), &STAMP)
extern int s6dns_engine_init_r (s6dns_engine_t *, s6dns_ip46list_t const *, uint32_t, char const *, unsigned int, uint16_t, s6dns_debughook_t const *, tain const *, tain const *) ;
#define s6dns_engine_init_r_g(dt, servers, options, q, qlen, qtype, dbh, deadline) s6dns_engine_init_r(dt, servers, options, q, qlen, qtype, dbh, (deadline), &STAMP)


 /* Call before iopause() */

extern void s6dns_engine_nextdeadline (s6dns_engine_t const *, tain *) ;
#define s6dns_engine_isreadable(dt) ((dt)->flagreading)
#define s6dns_engine_iswritable(dt) ((dt)->flagwriting)


 /* Call after iopause(): _timeout if iopause returns 0, _event otherwise */

extern int s6dns_engine_timeout (s6dns_engine_t *, tain const *) ;
#define s6dns_engine_timeout_g(dt) s6dns_engine_timeout((dt), &STAMP)
extern int s6dns_engine_event (s6dns_engine_t *, tain const *) ;
#define s6dns_engine_event_g(dt) s6dns_engine_event((dt), &STAMP)

extern void s6dns_engine_query (s6dns_engine_t const *, char **, uint16_t *, uint16_t *) ;
#define s6dns_engine_packet(dt) ((dt)->sa.s + (dt)->querylen)
#define s6dns_engine_packetlen(dt) ((unsigned int)((dt)->sa.len - (dt)->querylen))


#endif
