/* ISC license. */

#ifndef SKADNS_H
#define SKADNS_H

#include <stdint.h>
#include <errno.h>
#include <skalibs/tai.h>
#include <skalibs/genalloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/textclient.h>
#include <s6-dns/config.h>
#include <s6-dns/s6dns-domain.h>

#define SKADNSD_PROG S6_DNS_EXTBINPREFIX "skadnsd"
#define SKADNS_BANNER1 "skadns v1.0 (b)\n"
#define SKADNS_BANNER1_LEN (sizeof SKADNS_BANNER1 - 1)
#define SKADNS_BANNER2 "skadns v1.0 (a)\n"
#define SKADNS_BANNER2_LEN (sizeof SKADNS_BANNER2 - 1)
#define SKADNS_MAXCONCURRENCY 1000

typedef struct skadnsanswer_s skadnsanswer_t, *skadnsanswer_t_ref ;
struct skadnsanswer_s
{
  int status ;
  char *data ;
  unsigned int len ;
} ;
#define SKADNSANSWER_ZERO { .status = EINVAL, .data = 0, .len = 0 }

typedef struct skadns_s skadns_t, *skadns_t_ref ;
struct skadns_s
{
  textclient_t connection ;
  genalloc list ; /* array of uint16_t */
  gensetdyn q ; /* set of skadnsanswer_t */
} ;
#define SKADNS_ZERO { .connection = TEXTCLIENT_ZERO, .list = GENALLOC_ZERO, .q = GENSETDYN_INIT(skadnsanswer_t, 3, 3, 8) }
extern skadns_t const skadns_zero ;


 /* Starting and ending a session */

extern int skadns_start (skadns_t *, char const *, tain_t const *, tain_t *) ;
#define skadns_start_g(a, path, deadline) skadns_start(a, path, (deadline), &STAMP)
extern int skadns_startf (skadns_t *, tain_t const *, tain_t *) ;
#define skadns_startf_g(a, deadline) skadns_startf(a, (deadline), &STAMP)
extern void skadns_end (skadns_t *) ;

                
 /* Synchronous functions */
 
extern int skadns_send (skadns_t *, uint16_t *, s6dns_domain_t const *, uint16_t, tain_t const *, tain_t const *, tain_t *) ;
#define skadns_send_g(a, id, d, qtype, limit, deadline) skadns_send(a, id, d, qtype, limit, (deadline), &STAMP)
extern int skadns_cancel (skadns_t *, uint16_t, tain_t const *, tain_t *) ;
#define skadns_cancel_g(a, id, deadline) skadns_cancel(a, id, (deadline), &STAMP)


 /* Asynchronous functions */

#define skadns_fd(a) textclient_fd(&(a)->connection)
extern int skadns_update (skadns_t *) ;
#define skadns_list(a) genalloc_s(uint16_t const, &(a)->list)
#define skadns_clearlist(a) ((a)->list.len = 0)
extern int skadns_packetlen (skadns_t const *, uint16_t) ;
extern char const *skadns_packet (skadns_t const *, uint16_t) ;
extern int skadns_release (skadns_t *, uint16_t) ;

#endif
