/* ISC license. */

#include <sys/uio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#include <skalibs/types.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/genalloc.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/iopause.h>
#include <skalibs/textmessage.h>
#include <skalibs/textclient.h>

#include <s6-dns/s6dns.h>
#include <s6-dns/skadns.h>

typedef struct dnsio_s dnsio, *dnsio_ref ;
struct dnsio_s
{
  size_t xindex ;
  s6dns_engine_t dt ;
  uint16_t id ;
} ;
#define DNSIO_ZERO { .xindex = 0, .dt = S6DNS_ENGINE_ZERO, .id = 0 }

static genalloc g = GENALLOC_ZERO ; /* dnsio */

static inline void dnsio_free (dnsio *p)
{
  s6dns_engine_free(&p->dt) ;
}

static void dnsio_remove (size_t i)
{
  size_t n = genalloc_len(dnsio, &g) ;
  dnsio *a = genalloc_s(dnsio, &g) ;
  dnsio_free(a + i) ;
  if (--n) a[i] = a[n] ;
  genalloc_setlen(dnsio, &g, n) ;
}

static void fail (size_t i)
{
  dnsio *p = genalloc_s(dnsio, &g) + i ;
  char pack[3] ;
  uint16_pack_big(pack, p->id) ;
  pack[2] = p->dt.status ;
  dnsio_remove(i) ;
  if (!textmessage_put(textmessage_sender_x, pack, 3))
    strerr_diefu1sys(111, "textmessage_put") ;
}

static void answer (char c)
{
  if (!textmessage_put(textmessage_sender_1, &c, 1))
    strerr_diefu1sys(111, "textmessage_put") ;
}

static int parse_protocol (struct iovec const *v, void *context)
{
  char const *s = v->iov_base ;
  uint16_t id ;
  if (v->iov_len < 3) strerr_dief1x(100, "invalid client request") ;
  uint16_unpack_big(s, &id) ;
  switch (s[2])  /* protocol parsing */
  {
    case 'Q' : /* send a query */
    {
      dnsio *p ;
      size_t n = genalloc_len(dnsio, &g) ;
      tain limit ;
      uint16_t qtype ;
      if (v->iov_len < 21)
        strerr_dief1x(100, "invalid client request") ;
      if (!genalloc_readyplus(dnsio, &g, 1))
      {
        answer(ENOMEM) ;
        break ;
      }
      p = genalloc_s(dnsio, &g) + n ;
      p->dt = s6dns_engine_zero ;
      uint16_unpack_big(s + 3, &qtype) ;
      if (memcmp(s + 5, "\0\0\0\0\0\0\0\0\0\0\0", 12))
        tain_unpack(s + 5, &limit) ;
      else tain_add_g(&limit, &tain_infinite_relative) ;
      if (!s6dns_engine_init_g(&p->dt, &s6dns_rci_here.servers, 1, s + 17, v->iov_len - 17, qtype, &limit))
      {
        answer(errno) ;
        break ;
      }
      p->id = id ;
      genalloc_setlen(dnsio, &g, n+1) ;
      answer(0) ;
      break ;
    }
    case 'q' : /* cancel a query */
    {
      dnsio *a = genalloc_s(dnsio, &g) ;
      size_t n = genalloc_len(dnsio, &g) ;
      size_t i = 0 ;
      for (; i < n ; i++) if (a[i].id == id) break ;
      if (i >= n)
      {
        answer(ENOENT) ;
        break ;
      }
      dnsio_remove(i) ;
      answer(0) ;
      break ;
    }
    default : strerr_dief1x(100, "invalid client request") ;
  }
  (void)context ;
  return 1 ;
}

int main (void)
{
  PROG = "skadnsd" ;

  if (ndelay_on(0) == -1 || ndelay_on(1) == -1)
    strerr_diefu1sys(111, "set fds nonblocking") ;
  if (!sig_altignore(SIGPIPE))
    strerr_diefu1sys(111, "ignore SIGPIPE") ;
  tain_now_set_stopwatch_g() ;

  if (!s6dns_rci_init(&s6dns_rci_here, "/etc/resolv.conf"))
    strerr_diefu1sys(111, "initialize structures from /etc/resolv.conf") ;

  {
    tain deadline ;
    tain_addsec_g(&deadline, 2) ;
    if (!textclient_server_01x_init_g(SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, &deadline))
      strerr_diefu1sys(111, "sync with client") ;
  }
                  
  for (;;)                
  {
    tain deadline = TAIN_INFINITE ;
    size_t n = genalloc_len(dnsio, &g) ;
    dnsio *a = genalloc_s(dnsio, &g) ;
    iopause_fd x[3 + n] ;
    int r ;
    
    x[0].fd = 0 ; x[0].events = IOPAUSE_EXCEPT | IOPAUSE_READ ;
    x[1].fd = 1 ; x[1].events = IOPAUSE_EXCEPT | (textmessage_sender_isempty(textmessage_sender_1) ? 0 : IOPAUSE_WRITE) ;
    x[2].fd = textmessage_sender_fd(textmessage_sender_x) ;
    x[2].events = IOPAUSE_EXCEPT | (textmessage_sender_isempty(textmessage_sender_x) ? 0 : IOPAUSE_WRITE) ;
    for (size_t i = 0 ; i < n ; i++)
    {
      size_t j = 3 + i ;
      s6dns_engine_nextdeadline(&a[i].dt, &deadline) ;
      x[j].fd = a[i].dt.fd ;
      x[j].events = 0 ;
      if (s6dns_engine_isreadable(&a[i].dt)) x[j].events |= IOPAUSE_READ ;
      if (s6dns_engine_iswritable(&a[i].dt)) x[j].events |= IOPAUSE_WRITE ;
      a[i].xindex = j ;
    }
    r = iopause_g(x, 3 + n, &deadline) ;
    if (r < 0) strerr_diefu1sys(111, "iopause") ;
    if (!r) 
    {
      for (size_t i = 0 ; i < genalloc_len(dnsio, &g) ; i++)
        if (s6dns_engine_timeout_g(&a[i].dt)) fail(i--) ;
      continue ;
    }

    if (x[1].revents & IOPAUSE_WRITE)
      if (!textmessage_sender_flush(textmessage_sender_1) && !error_isagain(errno))
        strerr_diefu1sys(111, "flush stdout") ;
    if (x[2].revents & IOPAUSE_WRITE)
      if (!textmessage_sender_flush(textmessage_sender_x) && !error_isagain(errno))
        strerr_diefu1sys(111, "flush asyncout") ;
                        
    for (size_t i = 0 ; i < genalloc_len(dnsio, &g) ; i++) if (x[a[i].xindex].revents)
    {
      int r = s6dns_engine_event_g(&a[i].dt) ;
      if (r < 0) fail(i--) ;
      else if (r)
      {
        char pack[3] ;
        struct iovec v[2] = { { .iov_base = pack, .iov_len = 3 }, { .iov_base = s6dns_engine_packet(&a[i].dt), .iov_len = s6dns_engine_packetlen(&a[i].dt) } } ;
        uint16_pack_big(pack, a[i].id) ;
        pack[2] = 0 ;
        if (!textmessage_putv(textmessage_sender_x, v, 2))
          strerr_diefu1sys(111, "textmessage_put") ;
        dnsio_remove(i--) ;
      }
    }

    if (!textmessage_receiver_isempty(textmessage_receiver_0) || x[0].revents & IOPAUSE_READ)
    {
      if (textmessage_handle(textmessage_receiver_0, &parse_protocol, 0) < 0)
      {
        if (errno == EPIPE) break ; /* normal exit */
        strerr_diefu1sys(111, "handle messages from client") ;
      }
    }
  }
  return 0 ;
}
