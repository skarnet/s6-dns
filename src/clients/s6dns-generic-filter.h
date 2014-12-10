/* ISC license. */

#ifndef SKADNS_GENERIC_FILTER_H
#define SKADNS_GENERIC_FILTER_H

#include <skalibs/uint16.h>
#include <skalibs/stralloc.h>
#include <s6-dns/s6dns-domain.h>

typedef unsigned int scan_func_t (s6dns_domain_t *, char const *) ;
typedef scan_func_t *scan_func_t_ref ;
typedef int fmt_func_t (stralloc *, char const *, unsigned int) ;
typedef fmt_func_t *fmt_func_t_ref ;

extern unsigned int s6dns_namescanner (s6dns_domain_t *, char const *) ;
extern int s6dns_domainformatter (stralloc *, char const *, unsigned int) ;
extern int s6dns_generic_filter_main (int, char const *const *, char const *const *, uint16, scan_func_t_ref, fmt_func_t_ref, char const *) ;

extern int flag4 ;
extern int flag6 ;

#endif
