/* ISC license. */

#include <sys/types.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/strerr.h>
#include <skalibs/fmtscan.h>
#include <skalibs/stralloc.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include "s6dns-generic-filter.h"

#define USAGE "s6-dnsname-filter [ -4 ] [ -6 ] [ -l lines ] [ -c concurrency ] [ -t timeout ] [ -f format ] [ -e errorformat ]"

static size_t ipscanner (s6dns_domain_t *d, char const *s)
{
  char ip[16] ;
  size_t pos ;
  if (flag6)
  {
    pos = ip6_scan(s, ip) ;
    if (pos)
    {
      s6dns_domain_arpafromip6(d, ip, 128) ;
      goto yes ;
    }
  }
  if (flag4)
  {
    pos = ip4_scan(s, ip) ;
    if (pos)
    {
      s6dns_domain_arpafromip4(d, ip) ;
      goto yes ;
    }
  }
  return (errno = 0, 0) ;
 yes:
  if (!s6dns_domain_encode(d)) return 0 ;
  return pos ;
}

typedef struct s6dns_domain1_s s6dns_domain1_t, *s6dns_domain1_t_ref ;
struct s6dns_domain1_s
{
  s6dns_domain_t d ;
  unsigned int got : 1 ;
} ;

static int s6dns_message_parse_answer_domain1 (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  if ((section == 2) && (rr->rtype == S6DNS_T_PTR))
  {
    s6dns_domain1_t *data = stuff ;
    unsigned int start = pos ;
    if (data->got) return 1 ;
    if (!s6dns_message_get_domain(&data->d, packet, packetlen, &pos)) return 0 ;
    if (rr->rdlength != pos - start) return (errno = EPROTO, 0) ;
    data->got = 1 ;
  }
  return 1 ;
}

static int domainformatter (stralloc *sa, char const *packet, unsigned int packetlen)
{
  s6dns_domain1_t data ;
  s6dns_message_header_t h ;
  int r ;
  data.got = 0 ;
  r = s6dns_message_parse(&h, packet, packetlen, &s6dns_message_parse_answer_domain1, &data) ;
  if (r <= 0) return r ;
  if (!data.got) return 1 ;
  if (!stralloc_readyplus(sa, data.d.len + 1)) return -1 ;
  sa->len += s6dns_domain_tostring(sa->s + sa->len, data.d.len + 1, &data.d) ;
  stralloc_0(sa) ;
  return 1 ;
}

int main (int argc, char const *const *argv, char const *const *envp)
{
  PROG = "s6-dnsname-filter" ;
  return s6dns_generic_filter_main(argc, argv, envp, S6DNS_T_PTR, &ipscanner, &domainformatter, USAGE) ;
}
