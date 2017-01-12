/* ISC license. */

#include <sys/types.h>
#include <skalibs/bytestr.h>
#include <skalibs/strerr2.h>
#include <skalibs/buffer.h>
#include <s6-dns/s6dns.h>

#define USAGE "s6-dnsqualify name"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  s6dns_domain_t d ;
  PROG = "s6-dnsqualify" ;
  if (argc < 2) dieusage() ;
  if (!s6dns_domain_fromstring(&d, argv[1], str_len(argv[1])))
    strerr_diefu2sys(100, "make a domain name from ", argv[1]) ;
  if (!s6dns_init()) strerr_diefu1sys(111, "s6dns_init") ;
  {
    s6dns_domain_t list[s6dns_rci_here.rulesnum] ;
    unsigned int n = s6dns_qualify(list, &d) ;
    if (!n) strerr_diefu2sys(111, "qualify ", argv[1]) ;
    {
      char buf[S6DNS_FMT_DOMAINLIST(n)] ;
      size_t len = s6dns_fmt_domainlist(buf, S6DNS_FMT_DOMAINLIST(n), list, n, "\n", 1) ;
      if (!len) strerr_diefu1sys(111, "format result") ;
      if (buffer_put(buffer_1, buf, len) < 0) goto err ;
    }
  }
  if (buffer_putflush(buffer_1, "\n", 1) < 0) goto err ;
  return 0 ;
 err:
  strerr_diefu1sys(111, "write to stdout") ;
}
