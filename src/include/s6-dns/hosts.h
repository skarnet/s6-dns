/* ISC license. */

#ifndef S6DNS_HOSTS_H
#define S6DNS_HOSTS_H

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-dns/s6dns-rci.h>

extern cdb s6dns_hosts_here ;

extern int s6dns_hosts_compile (int, int) ;

extern int s6dns_hosts_init (cdb *, char const *, char const *, char const *) ;
#define s6dns_hosts_free(c) cdb_free(c)


 /* IP to name */

extern int s6dns_hosts_name_r (cdb const *, char const *, stralloc *, genalloc *, int) ;
#define s6dns_hosts_name4_r(cdb, ip, sa, ga) s6dns_hosts_name_r(cdb, ip, sa, ga, 0)
#define s6dns_hosts_name6_r(cdb, ip, sa, ga) s6dns_hosts_name_r(cdb, ip, sa, (ga), 1)

#define s6dns_hosts_name(ip, sa, ga, is6) s6dns_hosts_name_r(&s6dns_hosts_here, (ip), sa, ga, is6)
#define s6dns_hosts_name4(ip, sa, ga) s6dns_hosts_name4_r(&s6dns_hosts_here, (ip), sa, ga)
#define s6dns_hosts_name6(ip, sa, ga) s6dns_hosts_name6_r(&s6dns_hosts_here, (ip), sa, ga)


 /* name to IP. noq: name is an fqdn. unq: name is unqualified. */

extern int s6dns_hosts_ip_string_r (cdb const *, char const *, stralloc *, unsigned int) ;
#define s6dns_hosts_ip_noq_r(c, name, sa, is6) s6dns_hosts_ip_string_r(c, name, sa, !!(is6))
#define s6dns_hosts_ip_unq_r(c, name, sa, is6) s6dns_hosts_ip_string_r(c, name, sa, (!!(is6)) | 2)

#define s6dns_hosts_ip_string(name, sa, flags) s6dns_hosts_ip_string_r(&s6dns_hosts_here, (name), sa, flags)
#define s6dns_hosts_ip_noq(name, sa, is6) s6dns_hosts_ip_noq_r(&s6dns_hosts_here, (name), sa, is6)
#define s6dns_hosts_ip_unq(name, sa, is6) s6dns_hosts_ip_unq_r(&s6dns_hosts_here, (name), sa, is6)

#define s6dns_hosts_a_string_r(c, name, sa, isunq) s6dns_hosts_ip_string_r(c, name, sa, !!(isunq) << 1)
#define s6dns_hosts_aaaa_string_r(c, name, sa, isunq) s6dns_hosts_ip_string_r(c, name, sa, (!!(isunq) << 1) | 1)
extern int s6dns_hosts_aaaaa_string_r (cdb const *, char const *, genalloc *, int) ;

#define s6dns_hosts_a_string(name, sa, isunq) s6dns_hosts_a_string_r(&s6dns_hosts_here, (name), sa, isunq)
#define s6dns_hosts_aaaa_string(name, sa, isunq) s6dns_hosts_aaaa_string_r(&s6dns_hosts_here, (name), sa, isunq)
#define s6dns_hosts_aaaaa_string(name, ga, isunq) s6dns_hosts_aaaaa_string_r(&s6dns_hosts_here, (name), ga, isunq)

#define s6dns_hosts_a_noq_r(c, name, sa) s6dns_hosts_a_string_r(c, name, (sa), 0)
#define s6dns_hosts_aaaa_noq_r(c, name, sa) s6dns_hosts_aaaa_string_r(c, name, (sa), 1)
#define s6dns_hosts_aaaaa_noq_r(c, name, ga) s6dns_hosts_aaaaa_string_r(c, name, (ga), 0)

#define s6dns_hosts_a_noq(name, sa) s6dns_hosts_a_noq_r(&s6dns_hosts_here, (name), sa)
#define s6dns_hosts_aaaa_noq(name, sa) s6dns_hosts_aaaa_noq_r(&s6dns_hosts_here, (name), sa)
#define s6dns_hosts_aaaaa_noq(name, ga) s6dns_hosts_aaaaa_noq_r(&s6dns_hosts_here, (name), ga)

#define s6dns_hosts_a_unq_r(c, name, sa) s6dns_hosts_a_string_r(c, name, (sa), 2)
#define s6dns_hosts_aaaa_unq_r(c, name, sa) s6dns_hosts_aaaa_string_r(c, name, (sa), 3)
#define s6dns_hosts_aaaaa_unq_r(c, name, ga) s6dns_hosts_aaaaa_string_r(c, name, (ga), 1)

#define s6dns_hosts_a_unq(name, sa) s6dns_hosts_a_unq_r(&s6dns_hosts_here, (name), sa)
#define s6dns_hosts_aaaa_unq(name, sa) s6dns_hosts_aaaa_unq_r(&s6dns_hosts_here, (name), sa)
#define s6dns_hosts_aaaaa_unq(name, ga) s6dns_hosts_aaaaa_unq_r(&s6dns_hosts_here, (name), ga)


 /* name to IP, with qualification */

extern int s6dns_hosts_ip_q_r (cdb const *, char const *, stralloc *, char const *, unsigned int, int) ;
#define s6dns_hosts_a_q_r(c, name, sa, rules, rulesnum) s6dns_hosts_ip_q_r(c, name, sa, rules, (rulesnum), 0)
#define s6dns_hosts_aaaa_q_r(c, name, sa, rules, rulesnum) s6dns_hosts_ip_q_r(c, name, sa, rules, (rulesnum), 1)
extern int s6dns_hosts_aaaaa_q_r (cdb const *, char const *, genalloc *, char const *, unsigned int) ;

#define s6dns_hosts_ip_q(name, sa, is6) s6dns_hosts_ip_q_r(&s6dns_hosts_here, (name), sa, s6dns_rci_here.rules.s, s6dns_rci_here.rulesnum, is6)
#define s6dns_hosts_a_q(name, sa) s6dns_hosts_a_q_r(&s6dns_hosts_here, (name), sa, s6dns_rci_here.rules.s, s6dns_rci_here.rulesnum)
#define s6dns_hosts_aaaa_q(name, sa) s6dns_hosts_aaaa_q_r(&s6dns_hosts_here, (name), sa, s6dns_rci_here.rules.s, s6dns_rci_here.rulesnum)
#define s6dns_hosts_aaaaa_q(name, ga) s6dns_hosts_aaaaa_q_r(&s6dns_hosts_here, (name), ga, s6dns_rci_here.rules.s, s6dns_rci_here.rulesnum)

#endif
