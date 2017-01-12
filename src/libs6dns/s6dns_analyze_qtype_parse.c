/* ISC license. */

#include <stdint.h>
#include <skalibs/uint16.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-analyze.h>

typedef struct lookuptable_s lookuptable_t, *lookuptable_t_ref ;
struct lookuptable_s
{
  char const *text ;
  uint16_t qtype ;
} ;

static lookuptable_t const table[] =
{
  { "ANY", S6DNS_T_ANY },
  { "A", S6DNS_T_A },
  { "NS", S6DNS_T_NS },
  { "CNAME", S6DNS_T_CNAME },
  { "SOA", S6DNS_T_SOA },
  { "PTR", S6DNS_T_PTR },
  { "HINFO", S6DNS_T_HINFO },
  { "MX", S6DNS_T_MX },
  { "TXT", S6DNS_T_TXT },
  { "AAAA", S6DNS_T_AAAA },
  { "SRV", S6DNS_T_SRV },
  { "RP", S6DNS_T_RP },
  { "SIG", S6DNS_T_SIG },
  { "KEY", S6DNS_T_KEY },
  { "AXFR", S6DNS_T_AXFR },
  { 0, 0 }
} ;

uint16_t s6dns_analyze_qtype_parse (char const *s)
{
  {
    uint16_t u ;
    if (uint160_scan(s, &u)) return u ;
  }
  {
    register lookuptable_t const *p = table ;
    for (; p->text ; p++) if (case_equals(s, p->text)) return p->qtype ;
  }
  return 0 ;
}
