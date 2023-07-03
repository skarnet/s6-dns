/* ISC license. */

#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <skalibs/posixplz.h>
#include <skalibs/cdb.h>
#include <skalibs/djbunix.h>

#include <s6-dns/hosts.h>

int s6dns_hosts_init (void)
{
  int fdr, fdw ;
  char tmp[24] = "/tmp/hosts.cdb:XXXXXX" ;
  int fdc = openc_read("/etc/hosts.cdb") ;
  if (fdc >= 0)
  {
    struct stat stc, str ;
    if (fstat(fdc, &stc) == -1) goto errc ;
    if (stat("/etc/hosts", &str) == -1)
    {
      if (errno == ENOENT) goto useit ;
      else goto errc ;
    }
    if (stc.st_mtim > str.st_mtim) goto useit ;
    fd_close(fdc) ;
  }
  fdr = openc_read("/etc/hosts") ;
  if (fdr == -1) return errno == ENOENT ? (errno = 0, 0) : -1 ;
  fdw = mkstemp(tmp) ;
  if (fdw == -1) goto errr ;
  if (!s6dns_hosts_compile(fdr, fdw)) goto errw ;
  if (lseek(fdw, 0, SEEK_SET) == -1) goto errw ;
  if (!cdb_init_fromfd(&s6dns_hosts_here, fdw)) goto errw ;
  fd_close(fdw) ;
  unlink_void(tmp) ;
  fd_close(fdr) ;
  return 1 ;

 errw:
  fd_close(fdw) ;
  unlink_void(tmp) ;
 errr:
  fd_close(fdr) ;
  return -1 ;

 errc:
  fd_close(fdc) ;
  return -1 ;

 useit:
  if (!cdb_init_fromfd(&s6dns_hosts_here, fdc))
  {
    fd_close(fdc) ;
    return 0 ;
  }
  fd_close(fdc) ;
  return 1 ;
}
