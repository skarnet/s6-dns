/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/random.h>

#include <s6-dns/s6dns-rci.h>
#include <s6-dns/hosts.h>
#include <s6-dns/s6dns-resolve.h>

#define USAGE "s6-dnsip4 [ -q ] [ -H | -h ] [ -r ] [ -t timeout ] domain"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  stralloc ips = STRALLOC_ZERO ;
  tain deadline ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flaghosts = 0 ;
  int flagunsort = 0 ;
  int r = 0 ;
  PROG = "s6-dnsip4" ;

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

  if (!s6dns_rci_init(&s6dns_rci_here, "/etc/resolv.conf"))
    strerr_diefu1sys(111, "initialize structures from /etc/resolv.conf") ;
  if (flaghosts)
  {
    flaghosts = s6dns_hosts_init(&s6dns_hosts_here, "/etc/hosts", "/etc/hosts.cdb", "/tmp/hosts.cdb") ;
    if (flaghosts == -1) strerr_diefu1sys(111, "initialize hosts database from /etc/hosts or /etc/hosts.cdb") ;
  }

  if (flaghosts)
  {
    r = flagqualify ? s6dns_hosts_a_q(argv[0], &ips) : s6dns_hosts_a_noq(argv[0], &ips) ;
    if (r == -1) strerr_diefu3sys(111, "look up ", argv[0], " in hosts database") ;
  }

  if (!r)
  {
    r = s6dns_resolve_a_g(&ips, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
    if (r == -1) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  }

  if (!ips.len) return 1 ;
  if (flagunsort) random_unsort(ips.s, ips.len / 4, 4) ;
  for (size_t i = 0 ; i < ips.len / 4 ; i++)
  {
    char fmt[IP4_FMT] ;
    size_t n = ip4_fmt(fmt, ips.s + 4 * i) ;
    fmt[n++] = '\n' ;
    if (buffer_put(buffer_1small, fmt, n) == -1)
      strerr_diefu1sys(111, "write to stdout") ;
  }
  if (!buffer_flush(buffer_1small))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
