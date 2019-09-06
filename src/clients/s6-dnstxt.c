/* ISC license. */

#include <string.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/skamisc.h>
#include <skalibs/random.h>
#include <s6-dns/s6dns.h>

#define USAGE "s6-dnstxt [ -q ] [ -r ] [ -t timeout ] name"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  stralloc quoted = STRALLOC_ZERO ;
  stralloc sa = STRALLOC_ZERO ;
  genalloc offsets = GENALLOC_ZERO ; /* array of size_t */
  tain_t deadline ;
  size_t n ;
  size_t i = 0 ;
  unsigned int t = 0 ;
  int flagqualify = 0 ;
  int flagunsort = 0 ;
  PROG = "s6-dnstxt" ;
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
  if (t) tain_from_millisecs(&deadline, t) ; else deadline = tain_infinite_relative ;

  tain_now_set_stopwatch_g() ;
  tain_add_g(&deadline, &deadline) ;
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
  {
    int r = s6dns_resolve_txt_g(&sa, &offsets, argv[0], strlen(argv[0]), flagqualify, &deadline) ;
    if (r < 0) strerr_diefu2sys((errno == ETIMEDOUT) ? 99 : 111, "resolve ", argv[0]) ;
    if (!r) strerr_diefu4x(2, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
  }
  n = genalloc_len(size_t, &offsets) ;
  if (!n) return 1 ;
  {
    size_t printable_offsets[n] ;
    for (i = 0 ; i < n ; i++)
    {
      size_t beg = genalloc_s(size_t, &offsets)[i] ;
      size_t end = (i < n-1 ? genalloc_s(size_t, &offsets)[i+1] : sa.len) - 1 ;
      printable_offsets[i] = quoted.len ;
      if (!string_quote(&quoted, sa.s + beg, end - beg) || !stralloc_0(&quoted))
        strerr_diefu2sys(111, "quote ", sa.s + beg) ;
    }
    genalloc_free(size_t, &offsets) ;
    stralloc_free(&sa) ;
    if (flagunsort) random_unsort((char *)printable_offsets, n, sizeof(size_t)) ;
    for (i = 0 ; i < n ; i++)
      if ((buffer_puts(buffer_1small, quoted.s + printable_offsets[i]) < 0)
       || (buffer_put(buffer_1small, "\n", 1) < 1))
        strerr_diefu1sys(111, "write to stdout") ;
  }
  stralloc_free(&quoted) ;
  if (!buffer_flush(buffer_1small))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
