/* ISC license. */

#ifndef SKADNS_GENERIC_FILTER_H
#define SKADNS_GENERIC_FILTER_H

#include <sys/types.h>
#include <stdint.h>

#include <skalibs/stralloc.h>

#include <s6-dns/s6dns-domain.h>

typedef size_t scan_func (s6dns_domain_t *, char const *) ;
typedef scan_func *scan_func_ref ;
typedef int fmt_func (stralloc *, char const *, unsigned int) ;
typedef fmt_func *fmt_func_ref ;

extern size_t s6dns_namescanner (s6dns_domain_t *, char const *) ;
extern int s6dns_domainformatter (stralloc *, char const *, unsigned int) ;
extern int s6dns_generic_filter_main (int, char const *const *, char const *const *, uint16_t, scan_func_ref, fmt_func_ref, char const *) ;

extern int flag4 ;
extern int flag6 ;

#endif
