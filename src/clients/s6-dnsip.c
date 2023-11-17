/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/ip46.h>
#include <skalibs/genalloc.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/random.h>

#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsip [ -q ] [ -H | -h ] [ -r ] [ -t timeout ] domain"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc ips = GENALLOC_ZERO ;  /* ip46full */
  tain deadline ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flaghosts = 0 ;
  int flagunsort = 0 ;
  int r = 0 ;
  PROG = "s6-dnsip" ;

  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "qHhrt:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'q' : flagqualify = 1 ; break ;
        case 'H' : flaghosts = 0 ; break ;
        case 'h' : flaghosts = 1 ; break ;
        case 'r' : flagunsort = 1 ; break ;
        case 't' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (argc < 1) dieusage() ;

  tain_now_set_stopwatch_g() ;
  if (t) tain_from_millisecs(&deadline, t) ; else deadline = tain_infinite_relative ;
  tain_add_g(&deadline, &deadline) ;

  if (!s6dns_init_options(flaghosts))
    strerr_diefu1sys(111, "parse /etc/resolv.conf or /etc/hosts") ;

  if (flaghosts)
  {
    r = flagqualify ? s6dns_hosts_aaaaa_q(argv[0], &ips) : s6dns_hosts_aaaaa_noq(argv[0], &ips) ;
    if (r == -1) strerr_diefu3sys(111, "look up ", argv[0], " in hosts database") ;
  }

  if (!r)
  {
    r = s6dns_resolve_aaaaa_g(&ips, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
  }

  if (!genalloc_len(ip46full, &ips)) return 1 ;
  if (flagunsort) random_unsort(ips.s, genalloc_len(ip46full, &ips), sizeof(ip46full)) ;
  for (size_t i = 0 ; i < genalloc_len(ip46full, &ips) ; i++)
  {
    char fmt[IP6_FMT] ;
    size_t n = ip46full_fmt(fmt, genalloc_s(ip46full, &ips) + i) ;
    fmt[n++] = '\n' ;
    if (buffer_put(buffer_1small, fmt, n) < 0)
      strerr_diefu1sys(111, "write to stdout") ;
  }
  if (!buffer_flush(buffer_1small))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
