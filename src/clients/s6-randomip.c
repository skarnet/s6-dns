/* ISC license. */

#include <sys/types.h>
#include <errno.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>
#include <skalibs/random.h>

#define USAGE "s6-randomip [ -4 ] [ -6 ] [ -n number ]"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  char fmt[IP6_FMT] ;
  char ip[16] ;
  unsigned int n ;
  unsigned int i = 0 ;
  size_t what = 0 ;
  int finite = 0 ;
  PROG = "s6-randomip" ;
  for (;;)
  {
    int opt = lgetopt(argc, argv, "46n:") ;
    if (opt == -1) break ;
    switch (opt)
    {
      case '4' : what |= 1 ; break ;
      case '6' : what |= 2 ; break ;
      case 'n' :
        if (!uint0_scan(subgetopt_here.arg, &n)) dieusage() ;
        finite = 1 ;
        break ;
      default : dieusage() ;
    }
  }
  argc -= subgetopt_here.ind ; argv += subgetopt_here.ind ;
  if (!what) what = 1 ;
  what = 1 << (1 << what) ; 
  for (i = 0 ; !finite || (i < n) ; i++)
  {
    size_t len = what ;
    if (len > 16)
    {
      char c ;
      random_buf(&c, 1) ;
      len = (c & 1) ? 16 : 4 ;
    }
    random_buf(ip, len) ;
    len = (len == 16) ? ip6_fmt(fmt, ip) : ip4_fmt(fmt, ip) ;
    fmt[len++] = '\n' ;
    if (buffer_put(buffer_1, fmt, len) < (ssize_t)len)
      strerr_diefu1sys(111, "write to stdout") ;
  }
  if (!buffer_flush(buffer_1))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
