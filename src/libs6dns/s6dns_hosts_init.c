/* ISC license. */

#include <skalibs/bsdsnowflake.h>

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include <skalibs/posixplz.h>
#include <skalibs/stat.h>
#include <skalibs/cdb.h>
#include <skalibs/djbtime.h>
#include <skalibs/djbunix.h>

#include <s6-dns/hosts.h>

#include <skalibs/posixishard.h>

int s6dns_hosts_init (cdb *c, char const *txtfile, char const *cdbfile, char const *tmpprefix)
{
  int fdr ;
  int fdc = openc_read(cdbfile) ;
  if (fdc >= 0)
  {
    struct stat stc, str ;
    if (fstat(fdc, &stc) == -1) goto errc ;
    if (stat(txtfile, &str) == -1)
    {
      if (errno == ENOENT) goto useit ;
      else goto errc ;
    }
    if (timespec_cmp(&stc.st_mtim, &str.st_mtim) > 0) goto useit ;
    fd_close(fdc) ;
  }

  fdr = openc_read(txtfile) ;
  if (fdr == -1) return errno == ENOENT ? (errno = 0, 0) : -1 ;
  {
    int fdw ;
    size_t len = strlen(tmpprefix) ;
    char tmp[len + 8] ;
    memcpy(tmp, tmpprefix, len) ;
    memcpy(tmp + len, ":XXXXXX", 8) ;
    fdw = mkstemp(tmp) ;
    if (fdw == -1) goto errr ;
    if (!s6dns_hosts_compile(fdr, fdw)) goto errw ;
    if (lseek(fdw, 0, SEEK_SET) == -1) goto errw ;
    if (!cdb_init_fromfd(c, fdw)) goto errw ;
    fd_close(fdw) ;
    unlink_void(tmp) ;
    fd_close(fdr) ;
    return 1 ;

   errw:
    fd_close(fdw) ;
    unlink_void(tmp) ;
  }
 errr:
  fd_close(fdr) ;
  return -1 ;

 errc:
  fd_close(fdc) ;
  return -1 ;

 useit:
  if (!cdb_init_fromfd(c, fdc))
  {
    fd_close(fdc) ;
    return 0 ;
  }
  fd_close(fdc) ;
  return 1 ;
}
