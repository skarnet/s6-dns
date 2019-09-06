/* ISC license. */

#include <sys/types.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/tai.h>
#include <skalibs/iopause.h>
#include <skalibs/djbunix.h>
#include <skalibs/stralloc.h>
#include <skalibs/buffer.h>
#include <skalibs/bufalloc.h>
#include <skalibs/skamisc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/skadns.h>
#include "s6dns-generic-filter.h"

#define dieusage() strerr_dief1x(100, USAGE) ;

typedef struct line_s line_t, *line_t_ref ;
struct line_s
{
  stralloc swrd ;
  size_t wpos ;
  ssize_t dpos ;
  char w[2] ;
  unsigned int pending : 1 ;
} ;

#define LINE_ZERO { .swrd = STRALLOC_ZERO, .wpos = 0, .dpos = 0, .w = "\0", .pending = 0 }

static void line_recycle (line_t *l)
{
  l->swrd.len = 0 ;
  l->pending = 0 ;
}

int flag4 = 0 ;
int flag6 = 0 ;

int s6dns_generic_filter_main (int argc, char const *const *argv, char const *const *envp, uint16_t qtype, scan_func_t_ref scanner, fmt_func_t_ref formatter, char const *USAGE)
{
  skadns_t a = SKADNS_ZERO ;
  tain_t deadline, tto ;
  char const *normalformat = "%s=%d%w%r" ;
  char const *errorformat = "%s=<%e>%w%r" ;
  uint16_t maxlines = 256 ;
  uint16_t maxconn = 128 ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    unsigned int t = 0 ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, (qtype == S6DNS_T_PTR) ? "46l:c:t:f:e:" : "l:c:t:f:e:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '4' : flag4 = 1 ; break ;
        case '6' : flag6 = 1 ; break ;
        case 'l' : if (!uint160_scan(l.arg, &maxlines)) dieusage() ; break ;
        case 'c' : if (!uint160_scan(l.arg, &maxconn)) dieusage() ; break ;
        case 't' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        case 'f' : normalformat = l.arg ; break ;
        case 'e' : errorformat = l.arg ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (t) tain_from_millisecs(&tto, t) ; else tto = tain_infinite_relative ;
  }
  if (!flag4 && !flag6) flag4 = 1 ;
  if (maxconn < 1) maxconn = 1 ;
  if (maxconn > SKADNS_MAXCONCURRENCY) maxconn = SKADNS_MAXCONCURRENCY ;
  if (maxlines < maxconn) maxlines = maxconn ;

  tain_now_set_stopwatch_g() ;
  tain_addsec_g(&deadline, 2) ;
  if (!skadns_startf_g(&a, &deadline))
    strerr_diefu1sys(111, "establish skadns connection") ;
  if ((ndelay_on(0) < 0) || (ndelay_on(1) < 0))
    strerr_diefu1sys(111, "ndelay_on") ;

  {
    iopause_fd x[3] = { { .fd = 0, .events = 0, .revents = 0 }, { .fd = 1, .events = 0, .revents = 0 }, { .fd = skadns_fd(&a), .events = 0, .revents = 0 } } ;
    uint16_t lhead = 0, ltail = 0, numlines = 0, pending = 0 ;
    line_t storage[maxlines+1] ;
    uint16_t lineindex[maxconn] ;
    {
      line_t line_zero = LINE_ZERO ;
      char const *args[4] = { "", "", "", "" } ;
      uint16_t i = 0 ;
      for (; i <= maxlines ; i++) storage[i] = line_zero ;
      if (!string_format(&storage[0].swrd, "sdwr", normalformat, args)
       || !string_format(&storage[0].swrd, "sewr", errorformat, args))
        strerr_diefu1sys(111, "format a string") ;
      storage[0].swrd.len = 0 ;
    }

    for (;;)
    {
      x[0].events = !x[0].fd && (numlines < maxlines) && (pending < maxconn) ? IOPAUSE_READ : 0 ;
      x[1].events = bufalloc_len(bufalloc_1) ? IOPAUSE_WRITE : 0 ;
      x[2].events = pending ? IOPAUSE_READ : 0 ;
      if (!x[0].events && !x[1].events && !x[2].events) break ;
      tain_add_g(&deadline, &tain_infinite_relative) ;

      if (iopause_g(x + !(x[0].events & IOPAUSE_READ), 3 - !(x[0].events & IOPAUSE_READ), &deadline) < 0)
        strerr_diefu1sys(111, "iopause") ;


     /* Flush stdout */

      if (x[1].revents)
      {
        if (!bufalloc_flush(bufalloc_1) && !error_isagain(errno))
          strerr_diefu1sys(111, "write to stdout") ;
      }


     /* Get and format results from skadnsd */

      if (x[2].revents)
      {
	int j = 0 ;
        uint16_t const *list ;
        int n = skadns_update(&a) ;
        if (n < 0) strerr_diefu1sys(111, "skadns_update") ;
        list = skadns_list(&a) ;
        for (; j < n ; j++)
        {
          uint16_t i = lineindex[list[j]] ;
          char const *packet = skadns_packet(&a, list[j]) ;
          if (packet)
          {
            int r ;
            r = (*formatter)(&storage[i].swrd, packet, skadns_packetlen(&a, list[j])) ;
            if (r < 0) strerr_diefu1sys(111, "format skadns answer") ;
            if (!r) storage[i].dpos = -errno ;
          }
          else storage[i].dpos = -errno ;
          storage[i].pending = 0 ;
          skadns_release(&a, list[j]) ;
          pending-- ;
        }
        skadns_clearlist(&a) ;
      }


     /* Scan stdin and send queries to skadnsd */

      if (buffer_len(buffer_0) || (!x[0].fd && x[0].revents))
      {
        for (; (numlines < maxlines) && (pending < maxconn) ; lhead = (lhead+1) % (maxlines+1), numlines++)
        {
          s6dns_domain_t d ;
          line_t *line = storage + lhead ;
          int r = skagetln(buffer_0, &line->swrd, '\n') ;
          if (r < 0)
          {
            if (error_isagain(errno)) break ;
            if (errno != EPIPE) strerr_diefu1sys(111, "read from stdin") ;
            if (!stralloc_catb(&line->swrd, "\n", 1)) strerr_diefu1sys(111, "stralloc_catb") ;
            fd_close(x[0].fd) ;
            x[0].fd = -1 ;
            break ;
          }
          else if (!r)
          {
            fd_close(x[0].fd) ;
            x[0].fd = -1 ;
            break ;
          }
          line->swrd.s[line->swrd.len-1] = 0 ;
          line->wpos = (*scanner)(&d, line->swrd.s) ;
          if (!line->wpos)
          {
            line->wpos = line->swrd.len - 1 ;
            line->w[0] = 0 ;
            line->dpos = -errno ;
          }
          else
          {
            tain_t sendlimit ;
            uint16_t id ;
            line->w[0] = line->swrd.s[line->wpos] ;
            line->swrd.s[line->wpos] = 0 ;
            tain_addsec_g(&sendlimit, 2) ;
            tain_add_g(&deadline, &tto) ;
            if (!skadns_send_g(&a, &id, &d, qtype, &deadline, &sendlimit))
              line->dpos = -errno ;
            else
            {
              line->dpos = line->swrd.len ;
              lineindex[id] = lhead ;
              line->pending = 1 ;
              pending++ ;
            }
          }
        }
      }


     /* Send processed lines to stdout */

      for (; ltail != lhead ; ltail = (ltail+1) % (maxlines+1), numlines--)
      {
        char *args[4] ;
        line_t *line = storage + ltail ;
        if (line->pending) break ;
        args[0] = line->swrd.s ;
        args[1] = line->dpos < 0 ? (char *)s6dns_constants_error_str(-line->dpos) : line->swrd.s + line->dpos ;
        args[2] = line->w ;
        args[3] = line->swrd.s + line->wpos + !!line->w[0] ;
        if (!string_format(&bufalloc_1->x, line->dpos < 0 ? "sewr" : "sdwr", line->dpos < 0 ? errorformat : normalformat, (char const **)args))
          strerr_diefu1sys(111, "format output line") ;
        line_recycle(line) ;
        if (!bufalloc_put(bufalloc_1, "\n", 1))
          strerr_diefu1sys(111, "bufalloc_put") ;
      }
    }
  }

  (void)envp ;
  return 0 ;
}
