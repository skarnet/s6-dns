/* ISC license. */

#ifndef S6DNS_FMT_H
#define S6DNS_FMT_H

#include <sys/types.h>
#include <skalibs/types.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>

#define S6DNS_FMT_DOMAIN 256
#define s6dns_fmt_domain(s, max, d) s6dns_domain_tostring(s, max, d)

#define S6DNS_FMT_DOMAINLIST(n) ((n) * S6DNS_FMT_DOMAIN)
extern size_t s6dns_fmt_domainlist (char *, size_t, s6dns_domain_t const *, unsigned int, char const *, size_t) ;

#define S6DNS_FMT_HINFO 512
extern size_t s6dns_fmt_hinfo (char *, size_t, s6dns_message_rr_hinfo_t const *) ;

#define S6DNS_FMT_MX (S6DNS_FMT_DOMAIN + UINT16_FMT)
extern size_t s6dns_fmt_mx (char *, size_t, s6dns_message_rr_mx_t const *) ;

#define S6DNS_FMT_SOA (S6DNS_FMT_DOMAIN * 2 + 5 * UINT32_FMT)
extern size_t s6dns_fmt_soa (char *, size_t, s6dns_message_rr_soa_t const *) ;

#define S6DNS_FMT_SRV (S6DNS_FMT_DOMAIN + 3 * UINT16_FMT)
extern size_t s6dns_fmt_srv (char *, size_t, s6dns_message_rr_srv_t const *) ;

#endif
