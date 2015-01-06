/* ISC license. */

#include <errno.h>
#include <signal.h>
#include <skalibs/uint16.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/iopause.h>
#include <skalibs/unixmessage.h>
#include <skalibs/skaclient.h>
#include <s6-dns/s6dns.h>
#include <s6-dns/skadns.h>

typedef struct dnsio_s dnsio_t, *dnsio_t_ref ;
struct dnsio_s
{
  unsigned int xindex ;
  s6dns_engine_t dt ;
  uint16 id ;
} ;
#define DNSIO_ZERO { .xindex = SKADNS_MAXCONCURRENCY, .dt = S6DNS_ENGINE_ZERO, .id = 0 }

static dnsio_t a[SKADNS_MAXCONCURRENCY] ;
static unsigned int sp = 0 ;

static void remove (unsigned int i)
{
  dnsio_t tmp ;
  tmp = a[sp-1] ;
  a[--sp] = a[i] ;
  a[i] = tmp ;
}

static void fail (unsigned int i)
{
  char pack[3] ;
  unixmessage_t m = { .s = pack, .len = 3, .fds = 0, .nfds = 0 } ;
  uint16_pack_big(pack, a[i].id) ;
  pack[2] = a[i].dt.status ;
  s6dns_engine_recycle(&a[i].dt) ;
  remove(i) ;
  if (!unixmessage_put(unixmessage_sender_x, &m))
    strerr_diefu1sys(111, "unixmessage_put") ;
}

static void answer (char c)
{
  unixmessage_t m = { .s = &c, .len = 1, .fds = 0, .nfds = 0 } ;
  if (!unixmessage_put(unixmessage_sender_1, &m))
    strerr_diefu1sys(111, "unixmessage_put") ;
}

static int parse_protocol (unixmessage_t const *m, void *context)
{
  uint16 id ;
  if (m->len < 3 || m->nfds) strerr_dief1x(100, "invalid client request") ;
  uint16_unpack_big(m->s, &id) ;
  switch (m->s[2])  /* protocol parsing */
  {
    case 'Q' : /* send a query */
    {
      tain_t limit ;
      uint16 qtype ;
      if (m->len < 21) strerr_dief1x(100, "invalid client request") ;
      if (sp >= SKADNS_MAXCONCURRENCY)
      {
        answer(ENFILE) ;
        break ;
      }
      uint16_unpack_big(m->s + 3, &qtype) ;
      if (byte_diff(m->s + 5, 12, "\0\0\0\0\0\0\0\0\0\0\0"))
        tain_unpack(m->s + 5, &limit) ;
      else tain_add_g(&limit, &tain_infinite_relative) ;
      if (!s6dns_engine_init_g(&a[sp].dt, &s6dns_rci_here.servers, 1, m->s + 17, m->len - 17, qtype, &limit))
      {
        answer(errno) ;
        break ;
      }
      a[sp++].id = id ;
      answer(0) ;
      break ;
    }
    case 'q' : /* cancel a query */
    {
      register unsigned int i = 0 ;
      for (; i < sp ; i++) if (a[i].id == id) break ;
      if (i >= sp)
      {
        answer(ENOENT) ;
        break ;
      }
      s6dns_engine_recycle(&a[i].dt) ;
      remove(i) ;
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

  if (ndelay_on(0) < 0) strerr_diefu2sys(111, "ndelay_on ", "0") ;
  if (ndelay_on(1) < 0) strerr_diefu2sys(111, "ndelay_on ", "1") ;
  if (sig_ignore(SIGPIPE) < 0) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  tain_now_g() ;
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;

  {
    tain_t deadline ;
    tain_addsec_g(&deadline, 2) ;
    if (!skaclient_server_01x_init_g(SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, &deadline))
      strerr_diefu1sys(111, "sync with client") ;
  }
  {
    static dnsio_t const zero = DNSIO_ZERO ;
    register unsigned int i = 0 ;
    for (; i < SKADNS_MAXCONCURRENCY ; i++) a[i] = zero ;
  }
                  
  for (;;)                
  {
    iopause_fd x[3 + sp] ;
    register int r ;
    
    x[0].fd = 0 ; x[0].events = IOPAUSE_EXCEPT | IOPAUSE_READ ;
    x[1].fd = 1 ; x[1].events = IOPAUSE_EXCEPT | (unixmessage_sender_isempty(unixmessage_sender_1) ? 0 : IOPAUSE_WRITE) ;
    x[2].fd = unixmessage_sender_fd(unixmessage_sender_x) ;
    x[2].events = IOPAUSE_EXCEPT | (unixmessage_sender_isempty(unixmessage_sender_x) ? 0 : IOPAUSE_WRITE) ;
    {
      tain_t deadline = TAIN_INFINITE ;
      register unsigned int i = 0 ;
      for (; i < sp ; i++)
      {
        register unsigned int j = 3 + i ;
        s6dns_engine_nextdeadline(&a[i].dt, &deadline) ;
        x[j].fd = a[i].dt.fd ;
        x[j].events = 0 ;
        if (s6dns_engine_isreadable(&a[i].dt)) x[j].events |= IOPAUSE_READ ;
        if (s6dns_engine_iswritable(&a[i].dt)) x[j].events |= IOPAUSE_WRITE ;
        a[i].xindex = j ;
      }
      r = iopause_g(x, 3 + sp, &deadline) ;
    }
    if (r < 0) strerr_diefu1sys(111, "iopause") ;
    if (!r) 
    {
      register unsigned int i = 0 ;
      for (; i < sp ; i++)
        if (s6dns_engine_timeout_g(&a[i].dt)) fail(i--) ;
      continue ;
    }

    if (x[1].revents & IOPAUSE_WRITE)
      if (!unixmessage_sender_flush(unixmessage_sender_1) && !error_isagain(errno))
        strerr_diefu1sys(111, "flush stdout") ;
    if (x[2].revents & IOPAUSE_WRITE)
      if (!unixmessage_sender_flush(unixmessage_sender_x) && !error_isagain(errno))
        strerr_diefu1sys(111, "flush asyncout") ;
                        
    {
      register unsigned int i = 0 ;
      for (; i < sp ; i++) if (x[a[i].xindex].revents)
      {
        register int r = s6dns_engine_event_g(&a[i].dt) ;
        if (r < 0) fail(i--) ;
        else if (r)
        {
          char pack[3] ;
          siovec_t v[2] = { { .s = pack, .len = 3 }, { .s = s6dns_engine_packet(&a[i].dt), .len = s6dns_engine_packetlen(&a[i].dt) } } ;
          unixmessage_v_t mv = { .v = v, .vlen = 2, .fds = 0, .nfds = 0 } ;
          uint16_pack_big(pack, a[i].id) ;
          pack[2] = 0 ;
          if (!unixmessage_putv(unixmessage_sender_x, &mv))
            strerr_diefu1sys(111, "unixmessage_put") ;
          s6dns_engine_recycle(&a[i].dt) ;
          remove(i--) ;
        }
      }
    }

    if (!unixmessage_receiver_isempty(unixmessage_receiver_0) || x[0].revents & IOPAUSE_READ)
    {
      if (unixmessage_handle(unixmessage_receiver_0, &parse_protocol, 0) < 0)
      {
        if (errno == EPIPE) break ; /* normal exit */
        strerr_diefu1sys(111, "handle messages from client") ;
      }
    }
  }
  return 0 ;
}
