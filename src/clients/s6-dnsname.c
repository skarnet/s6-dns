/* ISC license. */

#include <sys/types.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>
#include <skalibs/tai.h>
#include <skalibs/genalloc.h>
#include <skalibs/ip46.h>
#include <skalibs/random.h>

#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsname [ -4 | -6 ] [ -H | -h ] [ -r ] [ -t timeout ] ip"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc ds = GENALLOC_ZERO ; /* array of s6dns_domain_t */
  tain deadline ;
  ip46full ip = IP46FULL_ZERO ;
  unsigned int t = 0 ;
  int flaghosts = 0 ;
  int flagunsort = 0 ;
  int do4 = 0 ;
  int do6 = 0 ;
  PROG = "s6-dnsname" ;

  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "46Hhrt:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '4' : do4 = 1 ; break ;
        case '6' : do6 = 1 ; break ;
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

  if (!do4 && !do6) do4 = do6 = 1 ;
  if (do4 && do6)
  {
    if (!ip46full_scan(argv[0], &ip)) dieusage() ;
  }
  else if (do6)
  {
    if (!ip6_scan(argv[0], ip.ip)) dieusage() ;
    ip.is6 = 1 ;
  }
  else if (!ip4_scan(argv[0], ip.ip)) dieusage() ;

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
    stralloc sa = STRALLOC_ZERO ;
    int r = s6dns_hosts_name(ip.ip, &sa, &ds, ip.is6) ;
    if (r == -1) strerr_diefu3sys(111, "look up ", argv[0], " in hosts database") ;
    if (r)
    {
      for (size_t i = 0 ; i < genalloc_len(size_t, &ds) ; i++)
      {
        if (buffer_puts(buffer_1, sa.s + genalloc_s(size_t, &ds)[i]) < 0
         || buffer_put(buffer_1, "\n", 1) < 0) goto err ;
      }
      if (!buffer_flush(buffer_1)) goto err ;
      return 0 ;
    }
  }

  {
    int r = ip.is6 ? s6dns_resolve_name6_g(&ds, ip.ip, &deadline) : s6dns_resolve_name4_g(&ds, ip.ip, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  }

  if (!genalloc_len(s6dns_domain_t, &ds)) return 1 ;
  if (flagunsort) random_unsort(ds.s, genalloc_len(s6dns_domain_t, &ds), sizeof(s6dns_domain_t)) ;
  {
    char buf[S6DNS_FMT_DOMAINLIST(genalloc_len(s6dns_domain_t, &ds))] ;
    size_t len = s6dns_fmt_domainlist(buf, S6DNS_FMT_DOMAINLIST(genalloc_len(s6dns_domain_t, &ds)), genalloc_s(s6dns_domain_t, &ds), genalloc_len(s6dns_domain_t, &ds), "\n", 1) ;
    if (!len) strerr_diefu1sys(111, "format result") ;
    if (buffer_put(buffer_1, buf, len) < (ssize_t)len) goto err ;
  }
  if (buffer_putflush(buffer_1, "\n", 1) < 1) goto err ;
  return 0 ;

 err:
  strerr_diefu1sys(111, "write to stdout") ;
}
