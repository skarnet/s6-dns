/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/strerr2.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/genwrite.h>
#include <skalibs/tai.h>
#include <s6-dns/s6dns.h>
#include <s6-dns/s6dns-analyze.h>
#include <s6-dns/s6dns-debug.h>

#define USAGE "s6-dnsqr [ -1 | -2 ] [ -t timeout ] [ -D debuglevel ] qtype query"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  tain_t deadline ;
  unsigned int debuglevel = 0 ;
  genwrite_t *where = &genwrite_stderr ;
  PROG = "s6-dnsqr" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    unsigned int t = 0 ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "12t:D:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '1' : where = &genwrite_stdout ; break ;
        case '2' : where = &genwrite_stderr ; break ;
        case 't' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        case 'D' : if (!uint0_scan(l.arg, &debuglevel)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (t) tain_from_millisecs(&deadline, t) ; else deadline = tain_infinite_relative ;
  }
  if (argc < 2) dieusage() ;
  {
    s6dns_debughook_t dbh = { .post_recv = 0, .pre_send = 0, .post_send = 0 } ;
    s6dns_domain_t d ;
    uint16_t qtype = s6dns_analyze_qtype_parse(argv[0]) ;
    if (!qtype) dieusage() ;
    if (!s6dns_domain_fromstring_noqualify_encode(&d, argv[1], strlen(argv[1])))
      strerr_diefu2sys(100, "encode ", argv[1]) ;
    dbh.external = where ;
    if (debuglevel & 1) dbh.post_recv = &s6dns_debug_dumpdt_post_recv ;
    if (debuglevel & 2) { dbh.pre_send = &s6dns_debug_dumpdt_pre_send ; dbh.post_send = &s6dns_debug_dumpdt_post_send ; }
    tain_now_set_stopwatch_g() ;
    tain_add_g(&deadline, &deadline) ;
    if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
    if (!s6dns_resolve_core_r_g(&d, qtype, &s6dns_engine_here, &s6dns_rci_here.servers, &dbh, &deadline))
    {
      char fmt[UINT16_FMT] ;
      fmt[uint16_fmt(fmt, qtype)] = 0 ;
      strerr_diefu6x((errno == ETIMEDOUT) ? 99 : 2, "resolve query ", argv[1], " of qtype ", fmt, ": ", s6dns_constants_error_str(errno)) ;
    }
  }
  if (!s6dns_analyze_packet(&genwrite_stdout, s6dns_engine_packet(&s6dns_engine_here), s6dns_engine_packetlen(&s6dns_engine_here), 1))
  {
    int e = errno ;
    buffer_flush(buffer_1) ;
    errno = e ;
    strerr_diefu1sys(111, "analyze response") ;
  }
  if (!buffer_flush(buffer_1)) strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
