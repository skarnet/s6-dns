/* ISC license. */

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdio.h>

#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/djbunix.h>

#include <s6-dns/hosts.h>

#define USAGE "s6-dns-hosts-compile [ -i ifile ] [ -o ofile ]"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  char const *ifile = "/etc/hosts" ;
  char const *ofile = "/etc/hosts.cdb" ;
  PROG = "s6-dns-hosts-compile" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "i:o:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'i' : ifile = l.arg ; break ;
        case 'o' : ofile = l.arg ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }

  {
    int fdr, fdw ;
    size_t len = strlen(ofile) ;
    char tmp[len + 29] ;
    memcpy(tmp, ofile, len) ;
    memcpy(tmp + len, ":s6-dns-hosts-compile:XXXXXX", 29) ;
    fdr = openc_read(ifile) ;
    if (fdr == -1) strerr_diefu2sys(111, "open ", ifile) ;
    fdw = mkstemp(tmp) ;
    if (fdw == -1) strerr_diefu2sys(111, "create ", tmp) ;
    if (!s6dns_hosts_compile(fdr, fdw))
      strerr_diefu4sys(111, "compile ", ifile, " to ", tmp) ;
    if (fsync(fdw) == -1) strerr_diefu2sys(111, "fsync ", tmp) ;
    if (fchmod(fdw, 0644) == -1) strerr_diefu2sys(111, "fchmod ", tmp) ;
    if (rename(tmp, ofile) == -1) strerr_diefu4sys(111, "rename ", tmp, " to ", ofile) ;
  }
  return 0 ;
}
