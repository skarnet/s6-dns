/* ISC license. */

#include <s6-dns/s6dns-analyze.h>

static s6dns_analyze_rtypetable_t const s6dns_analyze_rtypetable_array[] =
{
  { 1, "A", &s6dns_analyze_record_a },
  { 2, "NS", &s6dns_analyze_record_domain },
  { 5, "CNAME", &s6dns_analyze_record_domain },
  { 6, "SOA", &s6dns_analyze_record_soa },
  { 12, "PTR", &s6dns_analyze_record_domain },
  { 13, "HINFO", &s6dns_analyze_record_hinfo },
  { 15, "MX", &s6dns_analyze_record_mx },
  { 16, "TXT", &s6dns_analyze_record_strings },
  { 28, "AAAA", &s6dns_analyze_record_aaaa },
  { 33, "SRV", &s6dns_analyze_record_srv },
  { 257, "CAA", &s6dns_analyze_record_caa },
  { 0, "unknown", &s6dns_analyze_record_unknown }
} ;

s6dns_analyze_rtypetable_t const *s6dns_analyze_rtypetable = s6dns_analyze_rtypetable_array ;
