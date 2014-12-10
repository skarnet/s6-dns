/* ISC license. */

#ifndef S6DNS_ANALYZE_H
#define S6DNS_ANALYZE_H

#include <skalibs/uint16.h>
#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-message.h>

typedef int s6dns_analyze_record_func_t (genwrite_t *, s6dns_message_rr_t const *, char const *, unsigned int, unsigned int) ;
typedef s6dns_analyze_record_func_t *s6dns_analyze_record_func_t_ref ;

typedef struct s6dns_analyze_rtypetable_s s6dns_analyze_rtypetable_t, *s6dns_analyze_rtypetable_t_ref ;
struct s6dns_analyze_rtypetable_s
{
  uint16 rtype ;
  char const *string ;
  s6dns_analyze_record_func_t_ref f ;
} ;

extern uint16 s6dns_analyze_qtype_parse (char const *) ;

extern s6dns_analyze_rtypetable_t const *s6dns_analyze_rtypetable ;

extern s6dns_analyze_record_func_t s6dns_analyze_record_a ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_aaaa ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_hinfo ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_soa ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_mx ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_srv ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_domain ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_strings ;
extern s6dns_analyze_record_func_t s6dns_analyze_record_unknown ;

extern s6dns_analyze_record_func_t s6dns_analyze_record ;

extern int s6dns_analyze_packet (genwrite_t *, char const *, unsigned int, int) ;

#endif
