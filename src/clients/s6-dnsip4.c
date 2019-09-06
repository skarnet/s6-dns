/* ISC license. */

#include <string.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/random.h>
#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsip4 [ -q ] [ -r ] [ -t timeout ] domain"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  stralloc ips = STRALLOC_ZERO ;
  tain_t deadline ;
  size_t i = 0 ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flagunsort = 0 ;
  PROG = "s6-dnsip4" ;

  for (;;)
  {
    int opt = subgetopt(argc, argv, "qrt:") ;
    if (opt == -1) break ;
    switch (opt)
    {
      case 'q' : flagqualify = 1 ; break ;
      case 'r' : flagunsort = 1 ; break ;
      case 't' : if (!uint0_scan(subgetopt_here.arg, &t)) dieusage() ; break ;
      default : dieusage() ;
    }
  }
  argc -= subgetopt_here.ind ; argv += subgetopt_here.ind ;
  if (argc < 1) dieusage() ;

  tain_now_set_stopwatch_g() ;
  if (t) tain_from_millisecs(&deadline, t) ; else deadline = tain_infinite_relative ;
  tain_add_g(&deadline, &deadline) ;
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
  {
    int r = s6dns_resolve_a_g(&ips, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  }
  if (!ips.len) return 1 ;
  if (flagunsort) random_unsort(ips.s, ips.len / 4, 4) ;
  for (i = 0 ; i < ips.len / 4 ; i++)
  {
    char fmt[IP4_FMT] ;
    size_t n = ip4_fmt(fmt, ips.s + 4 * i) ;
    fmt[n++] = '\n' ;
    if (buffer_put(buffer_1small, fmt, n) < (ssize_t)n)
      strerr_diefu1sys(111, "write to stdout") ;
  }
  if (!buffer_flush(buffer_1small))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
