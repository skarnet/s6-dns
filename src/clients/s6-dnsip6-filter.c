/* ISC license. */

#include <string.h>
#include <skalibs/fmtscan.h>
#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>
#include "s6dns-generic-filter.h"

#define USAGE "s6-dnsip6-filter [ -l lines ] [ -c concurrency ] [ -t timeout ] [ -f format ] [ -e errorformat ]"

typedef struct s6dns_aaaa1_s s6dns_aaaa1_t, *s6dns_aaaa1_t_ref ;
struct s6dns_aaaa1_s
{
  char ip[16] ;
  unsigned int got : 1 ;
} ;

static int s6dns_message_parse_answer_aaaa1 (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  if ((section == 2) && (rr->rtype == S6DNS_T_AAAA) && (rr->rdlength == 16))
  {
    s6dns_aaaa1_t *data = stuff ;
    if (data->got) return 1 ;
    memcpy(data->ip, packet+pos, 16) ;
    data->got = 1 ;
  }
  (void)packetlen ;
  return 1 ;
}

static int ipformatter (stralloc *sa, char const *packet, unsigned int packetlen)
{
  s6dns_aaaa1_t data ;
  s6dns_message_header_t h ;
  int r ;
  data.got = 0 ;
  r = s6dns_message_parse(&h, packet, packetlen, &s6dns_message_parse_answer_aaaa1, &data) ;
  if (r <= 0) return r ;
  if (!data.got) return 1 ;
  if (!stralloc_readyplus(sa, IP6_FMT)) return -1 ;
  sa->len += ip6_fmt(sa->s + sa->len, data.ip) ;
  stralloc_0(sa) ;
  return 1 ;
}

int main (int argc, char const *const *argv, char const *const *envp)
{
  PROG = "s6-dnsip6-filter" ;
  return s6dns_generic_filter_main(argc, argv, envp, S6DNS_T_AAAA, &s6dns_namescanner, &ipformatter, USAGE) ;
}
