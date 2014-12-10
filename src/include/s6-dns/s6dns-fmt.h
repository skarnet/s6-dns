/* ISC license. */

#ifndef S6DNS_FMT_H
#define S6DNS_FMT_H

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

#define S6DNS_FMT_DOMAIN 256
#define s6dns_fmt_domain(s, max, d) s6dns_domain_tostring(s, max, d)

#define S6DNS_FMT_DOMAINLIST(n) ((n) * S6DNS_FMT_DOMAIN)
extern unsigned int s6dns_fmt_domainlist (char *, unsigned int, s6dns_domain_t const *, unsigned int, char const *, unsigned int) ;

#define S6DNS_FMT_HINFO 512
extern unsigned int s6dns_fmt_hinfo (char *, unsigned int, s6dns_message_rr_hinfo_t const *) ;

#define S6DNS_FMT_MX (S6DNS_FMT_DOMAIN + UINT16_FMT)
extern unsigned int s6dns_fmt_mx (char *, unsigned int, s6dns_message_rr_mx_t const *) ;

#define S6DNS_FMT_SOA (S6DNS_FMT_DOMAIN * 2 + 5 * UINT32_FMT)
extern unsigned int s6dns_fmt_soa (char *, unsigned int, s6dns_message_rr_soa_t const *) ;

#define S6DNS_FMT_SRV (S6DNS_FMT_DOMAIN + 3 * UINT16_FMT)
extern unsigned int s6dns_fmt_srv (char *, unsigned int, s6dns_message_rr_srv_t const *) ;

#endif
