/* ISC license. */

#include <errno.h>
#include <skalibs/tai.h>
#include <skalibs/iopause.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-resolve.h>

 /*
    This is basically a synchronous interface to s6dns_engine.
    It resolves n dts at the same time.
 */

int s6dns_resolven_loop (s6dns_engine_t *dt, unsigned int n, unsigned int or, tain_t const *deadline, tain_t *stamp)
{
  iopause_fd x[n] ;
  unsigned int count = 0 ;
  for (;;)
  {
    tain_t localdeadline = *deadline ; 
    register int r ;
    register unsigned int i = 0 ;
    register unsigned int j = 0 ;
    for (; i < n ; i++) if (dt[i].status == EAGAIN)
    {
      s6dns_engine_nextdeadline(dt + i, &localdeadline) ;
      x[j].fd = dt[i].fd ;
      x[j].events = (s6dns_engine_isreadable(dt + i) ? IOPAUSE_READ : 0) | (s6dns_engine_iswritable(dt + i) ? IOPAUSE_WRITE : 0) ;
      j++ ;
    }
    if (!j) break ;
    r = iopause_stamp(x, j, &localdeadline, stamp) ;
    if (r < 0) return -1 ;
    else if (!r)
    {
      if (tain_less(deadline, stamp)) return (errno = ETIMEDOUT, -1) ;
      for (i = 0 ; i < n ; i++) if (dt[i].status == EAGAIN)
        if (s6dns_engine_timeout(dt + i, stamp) && (or >= 2)) return i ;
    }
    else
    {
      for (i = 0 ; i < n ; i++) if (dt[i].status == EAGAIN)
      {
        r = s6dns_engine_event(dt + i, stamp) ;
        if (or)
        {
          if (r && ((r > 0) || (or >= 2))) return i ;
        }
        else if (r > 0) count++ ;
      }
    }
  }
  return or ? (errno = ENOENT, -1) : count ;
}
