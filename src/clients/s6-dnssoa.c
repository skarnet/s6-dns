/* ISC license. */

#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/genalloc.h>
#include <skalibs/random.h>
#include <s6-dns/s6dns.h>

#define USAGE "s6-dnssoa [ -q ] [ -r ] [ -t timeout ] name"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc soas = GENALLOC_ZERO ; /* array of s6dns_message_rr_soa_t */
  tain_t deadline ;
  size_t i = 0 ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flagunsort = 0 ;
  PROG = "s6-dnssoa" ;
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
    int r = s6dns_resolve_soa_g(&soas, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  }
  if (!genalloc_len(s6dns_message_rr_soa_t, &soas)) return 1 ;
  if (flagunsort) random_unsort(soas.s, genalloc_len(s6dns_message_rr_soa_t, &soas), sizeof(s6dns_message_rr_soa_t)) ;
  for (i = 0 ; i < genalloc_len(s6dns_message_rr_soa_t, &soas) ; i++)
  {
    char buf[S6DNS_FMT_SOA] ;
    size_t len = s6dns_fmt_soa(buf, S6DNS_FMT_SOA, genalloc_s(s6dns_message_rr_soa_t, &soas) + i) ;
    if (!len) strerr_diefu1sys(111, "format result") ;
    if (buffer_put(buffer_1, buf, len) < (ssize_t)len) goto err ;
    if (buffer_put(buffer_1, "\n", 1) < 1) goto err ;
  }
  if (!buffer_flush(buffer_1)) goto err ;
  return 0 ;
 err:
  strerr_diefu1sys(111, "write to stdout") ;
}
