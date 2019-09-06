/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>
#include <skalibs/tai.h>
#include <skalibs/genalloc.h>
#include <skalibs/ip46.h>
#include <skalibs/random.h>
#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsname [ -4 | -6 ] [ -r ] [ -t timeout ] ip"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc ds = GENALLOC_ZERO ; /* array of s6dns_domain_t */
  tain_t deadline ;
  ip46full_t ip = IP46FULL_ZERO ;
  unsigned int t = 0 ;
  int flagunsort = 0 ;
  int do4 = 0 ;
  int do6 = 0 ;
  PROG = "s6-dnsname" ;
  for (;;)
  {
    int opt = subgetopt(argc, argv, "46rt:") ;
    if (opt == -1) break ;
    switch (opt)
    {
      case '4' : do4 = 1 ; break ;
      case '6' : do6 = 1 ; break ;
      case 'r' : flagunsort = 1 ; break ;
      case 't' : if (!uint0_scan(subgetopt_here.arg, &t)) dieusage() ; break ;
      default : dieusage() ;
    }
  }
  argc -= subgetopt_here.ind ; argv += subgetopt_here.ind ;
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
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
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
