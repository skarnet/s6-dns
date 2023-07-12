/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/genalloc.h>
#include <skalibs/random.h>

#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsmx [ -q ] [ -r ] [ -t timeout ] name"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  genalloc mxs = GENALLOC_ZERO ; /* array of s6dns_message_rr_mx_t */
  tain deadline ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flagunsort = 0 ;
  int r ;
  PROG = "s6-dnsmx" ;

  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "qrt:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'q' : flagqualify = 1 ; break ;
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

  r = s6dns_resolve_mx_g(&mxs, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
  if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
  if (!r) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  if (!genalloc_len(s6dns_message_rr_mx_t, &mxs)) return 1 ;
  if (flagunsort) random_unsort(mxs.s, genalloc_len(s6dns_message_rr_mx_t, &mxs), sizeof(s6dns_message_rr_mx_t)) ;
  for (size_t i = 0 ; i < genalloc_len(s6dns_message_rr_mx_t, &mxs) ; i++)
  {
    char buf[S6DNS_FMT_MX] ;
    size_t len = s6dns_fmt_mx(buf, S6DNS_FMT_MX, genalloc_s(s6dns_message_rr_mx_t, &mxs) + i) ;
    if (!len) strerr_diefu1sys(111, "format result") ;
    if (buffer_put(buffer_1, buf, len) < (ssize_t)len) goto err ;
    if (buffer_put(buffer_1, "\n", 1) < 1) goto err ;
  }
  if (!buffer_flush(buffer_1)) goto err ;
  return 0 ;
 err:
  strerr_diefu1sys(111, "write to stdout") ;
}
