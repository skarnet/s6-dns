/* ISC license. */

#include <sys/uio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <skalibs/types.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/iopause.h>
#include <skalibs/textmessage.h>
#include <skalibs/textclient.h>
#include <s6-dns/s6dns.h>
#include <s6-dns/skadns.h>

typedef struct dnsio_s dnsio_t, *dnsio_t_ref ;
struct dnsio_s
{
  unsigned int xindex ;
  s6dns_engine_t dt ;
  uint16_t id ;
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
  uint16_pack_big(pack, a[i].id) ;
  pack[2] = a[i].dt.status ;
  s6dns_engine_recycle(&a[i].dt) ;
  remove(i) ;
  if (!textmessage_put(textmessage_sender_x, pack, 3))
    strerr_diefu1sys(111, "textmessage_put") ;
}

static void answer (char c)
{
  if (!textmessage_put(textmessage_sender_1, &c, 1))
    strerr_diefu1sys(111, "unixmessage_put") ;
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
      tain_t limit ;
      uint16_t qtype ;
      if (v->iov_len < 21) strerr_dief1x(100, "invalid client request") ;
      if (sp >= SKADNS_MAXCONCURRENCY)
      {
        answer(ENFILE) ;
        break ;
      }
      uint16_unpack_big(s + 3, &qtype) ;
      if (memcmp(s + 5, "\0\0\0\0\0\0\0\0\0\0\0", 12))
        tain_unpack(s + 5, &limit) ;
      else tain_add_g(&limit, &tain_infinite_relative) ;
      if (!s6dns_engine_init_g(&a[sp].dt, &s6dns_rci_here.servers, 1, s + 17, v->iov_len - 17, qtype, &limit))
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
      unsigned int i = 0 ;
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
  tain_now_set_stopwatch_g() ;
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;

  {
    tain_t deadline ;
    tain_addsec_g(&deadline, 2) ;
    if (!textclient_server_01x_init_g(SKADNS_BANNER1, SKADNS_BANNER1_LEN, SKADNS_BANNER2, SKADNS_BANNER2_LEN, &deadline))
      strerr_diefu1sys(111, "sync with client") ;
  }
  {
    static dnsio_t const zero = DNSIO_ZERO ;
    unsigned int i = 0 ;
    for (; i < SKADNS_MAXCONCURRENCY ; i++) a[i] = zero ;
  }
                  
  for (;;)                
  {
    iopause_fd x[3 + sp] ;
    int r ;
    
    x[0].fd = 0 ; x[0].events = IOPAUSE_EXCEPT | IOPAUSE_READ ;
    x[1].fd = 1 ; x[1].events = IOPAUSE_EXCEPT | (textmessage_sender_isempty(textmessage_sender_1) ? 0 : IOPAUSE_WRITE) ;
    x[2].fd = textmessage_sender_fd(textmessage_sender_x) ;
    x[2].events = IOPAUSE_EXCEPT | (textmessage_sender_isempty(textmessage_sender_x) ? 0 : IOPAUSE_WRITE) ;
    {
      tain_t deadline = TAIN_INFINITE ;
      unsigned int i = 0 ;
      for (; i < sp ; i++)
      {
        unsigned int j = 3 + i ;
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
      unsigned int i = 0 ;
      for (; i < sp ; i++)
        if (s6dns_engine_timeout_g(&a[i].dt)) fail(i--) ;
      continue ;
    }

    if (x[1].revents & IOPAUSE_WRITE)
      if (!textmessage_sender_flush(textmessage_sender_1) && !error_isagain(errno))
        strerr_diefu1sys(111, "flush stdout") ;
    if (x[2].revents & IOPAUSE_WRITE)
      if (!textmessage_sender_flush(textmessage_sender_x) && !error_isagain(errno))
        strerr_diefu1sys(111, "flush asyncout") ;
                        
    {
      unsigned int i = 0 ;
      for (; i < sp ; i++) if (x[a[i].xindex].revents)
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
          s6dns_engine_recycle(&a[i].dt) ;
          remove(i--) ;
        }
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
