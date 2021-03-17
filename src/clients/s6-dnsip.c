/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/ip46.h>
#include <skalibs/genalloc.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/random.h>
#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsip [ -q ] [ -r ] [ -t timeout ] domain"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc ips = GENALLOC_ZERO ;  /* ip46full_t */
  tain_t deadline ;
  size_t i = 0 ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flagunsort = 0 ;
  PROG = "s6-dnsip" ;

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
    int r = s6dns_resolve_aaaaa_g(&ips, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r && errno) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  }
  if (!genalloc_len(ip46full_t, &ips)) return 1 ;

  if (flagunsort) random_unsort(ips.s, genalloc_len(ip46full_t, &ips), sizeof(ip46full_t)) ;
  for (i = 0 ; i < genalloc_len(ip46full_t, &ips) ; i++)
  {
    char fmt[IP6_FMT] ;
    size_t n = ip46full_fmt(fmt, genalloc_s(ip46full_t, &ips) + i) ;
    fmt[n++] = '\n' ;
    if (buffer_put(buffer_1small, fmt, n) < (ssize_t)n)
      strerr_diefu1sys(111, "write to stdout") ;
  }
  if (!buffer_flush(buffer_1small))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
