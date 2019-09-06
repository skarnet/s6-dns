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

#define USAGE "s6-dnssrv [ -q ] [ -r ] [ -t timeout ] service protocol name"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc srvs = GENALLOC_ZERO ; /* array of s6dns_message_rr_srv_t */
  tain_t deadline ;
  size_t i = 0 ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flagunsort = 0 ;
  PROG = "s6-dnssrv" ;
  for (;;)
  {
    int opt = subgetopt(argc, argv, "qt:") ;
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
  if (argc < 3) dieusage() ;

  tain_now_set_stopwatch_g() ;
  if (t) tain_from_millisecs(&deadline, t) ; else deadline = tain_infinite_relative ;
  tain_add_g(&deadline, &deadline) ;
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
  {
    size_t n0 = strlen(argv[0]) ;
    size_t n1 = strlen(argv[1]) ;
    size_t n2 = strlen(argv[2]) ;
    int r ;
    char name[n0 + n1 + n2 + 5] ;
    name[0] = '_' ;
    memcpy(name + 1, argv[0], n0) ;
    name[n0 + 1] = '.' ;
    name[n0 + 2] = '_' ;
    memcpy(name + n0 + 3, argv[1], n1) ;
    name[n0 + n1 + 3] = '.' ;
    memcpy(name + n0 + n1 + 4, argv[2], n2) ;
    name[n0 + n1 + n2 + 4] = 0 ;
    r = s6dns_resolve_srv_g(&srvs, name, n0 + n1 + n2 + 4, flagqualify, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r) strerr_diefu4x(2, "resolve ", name, ": ", s6dns_constants_error_str(errno)) ;
  }
  if (!genalloc_len(s6dns_message_rr_srv_t, &srvs)) return 1 ;
  if (flagunsort) random_unsort(srvs.s, genalloc_len(s6dns_message_rr_srv_t, &srvs), sizeof(s6dns_message_rr_srv_t)) ;
  for (i = 0 ; i < genalloc_len(s6dns_message_rr_srv_t, &srvs) ; i++)
  {
    char buf[S6DNS_FMT_SRV] ;
    size_t len = s6dns_fmt_srv(buf, S6DNS_FMT_SRV, genalloc_s(s6dns_message_rr_srv_t, &srvs) + i) ;
    if (!len) strerr_diefu1sys(111, "format result") ;
    if (buffer_put(buffer_1, buf, len) < (ssize_t)len) goto err ;
    if (buffer_put(buffer_1, "\n", 1) < 1) goto err ;
  }
  if (!buffer_flush(buffer_1)) goto err ;
  return 0 ;
 err:
  strerr_diefu1sys(111, "write to stdout") ;
}
