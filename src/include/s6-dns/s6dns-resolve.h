 /* ISC license. */

#ifndef S6DNS_RESOLVE_H
#define S6DNS_RESOLVE_H

#include <stdint.h>
#include <errno.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-ip46.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-rci.h>

 /*
    Synchronous DNS resolution primitives.
    The non-reentrant functions are just wrappers around the reentrant ones,
    using globals for the parameters the user doesn't care about:
    s6dns_engine_here for the query storage (dt),
    s6dns_debughook_zero meaning no debugging needed,
    s6dns_rci_here for the resolv.conf information (qualification rules and
    initial cache IPs)
 */

 /*
    The basic s6dns_engine wrapper loop: takes an initted dt and resolves it.
 */

#define s6dns_resolve_loop(deadline, stamp) s6dns_resolve_loop_r(&s6dns_engine_here, (deadline), stamp)
#define s6dns_resolve_loop_g(deadline) s6dns_resolve_loop((deadline), &STAMP)
#define s6dns_resolve_loop_r(dt, deadline, stamp) (s6dns_resolven_loop(dt, 1, 2, deadline, stamp) < 0 ? 0 : (dt)->status ? (errno = (dt)->status, 0) : 1)
#define s6dns_resolve_loop_r_g(dt, deadline) s6dns_resolve_loop(dt, (deadline), &STAMP)


 /*  QoL functions for single-domain synchronous resolution. */

 /*
    The innermost one:
    Initializes the dt with the given data (d, qtype), then calls the loop.
 */

#define s6dns_resolve_core(d, qtype, deadline, stamp) s6dns_resolve_core_r(d, qtype, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_core_g(d, qtype, deadline) s6dns_resolve_core(d, qtype, (deadline), &STAMP)
extern int s6dns_resolve_core_r (s6dns_domain_t const *, uint16_t, s6dns_engine_t *, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolve_core_r_g(d, qtype, dt, servers, dbh, deadline) s6dns_resolve_core_r(d, qtype, dt, servers, dbh, (deadline), &STAMP)


 /*
    Just above. Calls s6dns_resolve_core() then feeds the result to s6dns_message_parse().
    Returns -1 if a resolving or parsing error occurs.
    Returns 0 if everything works but the result is empty for some reason (i.e. nxdomain).
    Returns 1 if everything works and there's an actual answer.
 */

#define s6dns_resolve_parse(d, qtype, parsefunc, parsedata, deadline, stamp) s6dns_resolve_parse_r(d, qtype, parsefunc, parsedata, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_parse_g(d, qtype, parsefunc, parsedata, deadline) s6dns_resolve_parse(d, qtype, parsefunc, parsedata, (deadline), &STAMP)
extern int s6dns_resolve_parse_r (s6dns_domain_t const *, uint16_t, s6dns_message_rr_func_t_ref, void *, s6dns_engine_t *, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolve_parse_r_g(d, qtype, parsefunc, parsedata, dt, servers, dbh, deadline) s6dns_resolve_parse_r(d, qtype, parsefunc, parsedata, dt, servers, dbh, (deadline), &STAMP)


 /*
    Resolution without qualification. Encoding/decoding included.
 */

#define s6dns_resolvenoq(name, len, qtype, parsefunc, parsedata, deadline, stamp) s6dns_resolvenoq_r(name, len, qtype, parsefunc, parsedata, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolvenoq_g(name, len, qtype, parsefunc, parsedata, deadline) s6dns_resolvenoq(name, len, qtype, parsefunc, parsedata, (deadline), &STAMP)
extern int s6dns_resolvenoq_r (char const *, size_t, uint16_t, s6dns_message_rr_func_t_ref, void *, s6dns_engine_t *, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolvenoq_r_g(name, len, qtype, parsefunc, parsedata, dt, servers, dbh, deadline) s6dns_resolvenoq_r(name, len, qtype, parsefunc, parsedata, dt, servers, dbh, (deadline), &STAMP)


 /*
    Resolution with qualification:
    Get a qualification list from a name, then resolve the list in parallel.
 */

#define s6dns_resolveq(name, len, qtype, parsefunc, parsedata, deadline, stamp) s6dns_resolveq_r(name, len, qtype, parsefunc, parsedata, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolveq_g(name, len, qtype, parsefunc, parsedata, deadline) s6dns_resolveq(name, len, qtype, parsefunc, parsedata, (deadline), &STAMP)
extern int s6dns_resolveq_r (char const *, size_t, uint16_t, s6dns_message_rr_func_t_ref, void *, s6dns_rci_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolveq_r_g(name, len, qtype, parsefunc, parsedata, rci, dbh, deadline) s6dns_resolveq_r(name, len, qtype, parsefunc, parsedata, rci, dbh, (deadline), &STAMP)


 /*
    The resolution primitive that calls s6dns_resolvenoq() if the
    qualif flag is cleared and s6dns_resolveq() if it is set.
 */

#define s6dns_resolve(name, len, qtype, parsefunc, parsedata, qualif, deadline, stamp) s6dns_resolve_r(name, len, qtype, parsefunc, parsedata, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_t const *, deadline, stamp)
#define s6dns_resolve_g(name, len, qtype, parsefunc, parsedata, qualif, deadline) s6dns_resolve(name, len, qtype, parsefunc, parsedata, qualif, (deadline), &STAMP)
#define s6dns_resolve_r(name, len, qtype, parsefunc, parsedata, qualif, dt, rci, dbh, deadline, stamp) ((qualif) ? s6dns_resolveq_r(name, len, qtype, parsefunc, parsedata, rci, dbh, deadline, stamp) : s6dns_resolvenoq_r(name, len, qtype, parsefunc, parsedata, dt, &(rci)->servers, dbh, deadline, stamp))
#define s6dns_resolve_r_g(name, len, qtype, parsefunc, parsedata, qualif, dt, rci, dbh, deadline) s6dns_resolve_r(name, len, qtype, parsefunc, parsedata, qualif, dt, rci, dbh, (deadline), &STAMP)


 /* How to perform both AAAA and A queries at the same time */

#define s6dns_resolvenoq_aaaaa(ips, name, len, deadline, stamp) s6dns_resolvenoq_aaaaa_r(ips, name, len, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolvenoq_aaaaa_g(ips, name, len, deadline) s6dns_resolvenoq_aaaaa(ips, name, len, (deadline), &STAMP)
extern int s6dns_resolvenoq_aaaaa_r(genalloc *, char const *, size_t, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolvenoq_aaaaa_r_g(ips, name, len, servers, dbh, deadline) s6dns_resolvenoq_aaaaa_r(ips, name, len, servers, dbh, (deadline), &STAMP)

#define s6dns_resolveq_aaaaa(ips, name, len, deadline, stamp) s6dns_resolveq_aaaaa_r(ips, name, len, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolveq_aaaaa_g(ips, name, len, deadline) s6dns_resolveq_aaaaa(ips, name, len, (deadline), &STAMP)
extern int s6dns_resolveq_aaaaa_r(genalloc *, char const *, size_t, s6dns_rci_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolveq_aaaaa_r_g(ips, name, len, rci, dbh, deadline) s6dns_resolvenoq_aaaaa_r(ips, name, len, rci, dbh, (deadline), &STAMP)


 /*
    Some high-level functions.
    Queries are automatically translated to domain form and encoded.
    Domains returned in a stralloc are automatically decoded.
    Warning: decoded domains all start with '.'
    The int flag decides if qualification is needed or not.
 */

 /*
   For A fields: the stralloc answer has 4 chars per IP4.
   For AAAA fields: the stralloc answer has 16 chars per IP6.
   For TXT fields (and other mpag stuff): the stralloc contains the strings
     and the genalloc contains a list of offsets into that stralloc.
   For other fields: the result is stored in a genalloc of the appropriate type.
 */

#define s6dns_resolve_a(ips, name, len, qualif, deadline, stamp) s6dns_resolve_a_r(ips, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_a_g(ips, name, len, qualif, deadline) s6dns_resolve_a(ips, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_a_r(ips, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_A, &s6dns_message_parse_answer_a, (ips), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_a_r_g(ips, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_a_r(ips, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_aaaa(ip6s, name, len, qualif, deadline, stamp) s6dns_resolve_aaaa_r(ip6s, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_aaaa_g(ip6s, name, len, qualif, deadline) s6dns_resolve_aaaa(ip6s, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_aaaa_r(ip6s, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_AAAA, &s6dns_message_parse_answer_aaaa, (ip6s), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_aaaa_r_g(ip6s, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_aaaa_r(ip6s, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_aaaaa(ips, name, len, qualif, deadline, stamp) s6dns_resolve_aaaaa_r(ips, name, len, qualif, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_aaaaa_g(ips, name, len, qualif, deadline) s6dns_resolve_aaaaa(ips, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_aaaaa_r(ips, name, len, qualif, rci, dbh, deadline, stamp) ((qualif) ? s6dns_resolveq_aaaaa_r(ips, name, len, rci, dbh, deadline, stamp) : s6dns_resolvenoq_aaaaa_r(ips, name, len, &(rci)->servers, dbh, deadline, stamp))
#define s6dns_resolve_aaaaa_r_g(ips, name, len, qualif, rci, dbh, deadline) s6dns_resolve_aaaaa_r(ips, name, len, qualif, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_ptr(ds, name, len, deadline, stamp) s6dns_resolve_ptr_r(ds, name, len, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_ptr_g(ds, name, len, deadline) s6dns_resolve_ptr(ds, name, len, (deadline), &STAMP)
#define s6dns_resolve_ptr_r(ds, name, len, dt, servers, dbh, deadline, stamp) s6dns_resolvenoq_r(name, len, S6DNS_T_PTR, &s6dns_message_parse_answer_domain, (ds), dt, servers, dbh, deadline, stamp)
#define s6dns_resolve_ptr_r_g(ds, name, len, dt, servers, dbh, deadline) s6dns_resolve_ptr_r(ds, name, len, dt, servers, dbh, (deadline), &STAMP)

#define s6dns_resolve_name4(ds, ip, deadline, stamp) s6dns_resolve_name4_r(ds, ip, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_name4_g(ds, ip, deadline) s6dns_resolve_name4(ds, ip, (deadline), &STAMP)
extern int s6dns_resolve_name4_r (genalloc *, char const *, s6dns_engine_t *, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolve_name4_r_g(ds, ip, dt, servers, dbh, deadline) s6dns_resolve_name4_r(ds, ip, dt, servers, dbh, (deadline), &STAMP)

#define s6dns_resolve_name6(ds, ip6, deadline, stamp) s6dns_resolve_name6_r(ds, ip6, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_name6_g(ds, ip6, deadline) s6dns_resolve_name6(ds, ip6, (deadline), &STAMP)
extern int s6dns_resolve_name6_r (genalloc *, char const *, s6dns_engine_t *, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolve_name6_r_g(ds, ip6, dt, servers, dbh, deadline) s6dns_resolve_name6_r(ds, ip6, dt, servers, dbh, (deadline), &STAMP)

#define s6dns_resolve_name46(ds, i, deadline, stamp) s6dns_resolve_name46_r(ds, i, &s6dns_engine_here, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_name46_g(ds, i, deadline) s6dns_resolve_name46(ds, i, (deadline), &STAMP)
#define s6dns_resolve_name46_r(ds, i, dt, servers, dbh, deadline, stamp) (ip46full_is6(i) ? s6dns_resolve_name6_r(ds, (i)->ip, dt, servers, dbh, deadline, stamp) : s6dns_resolve_name4_r(ds, (i)->ip, dt, servers, dbh, deadline, stamp))
#define s6dns_resolve_name46_r_g(ds, i, dt, servers, dbh, deadline) s6dns_resolve_name46_r(ds, i, dt, servers, dbh, (deadline), &STAMP)

#define s6dns_resolve_txt(sa, offsets, name, len, qualif, deadline, stamp) s6dns_resolve_txt_r(sa, offsets, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_txt_g(sa, offsets, name, len, qualif, deadline) s6dns_resolve_txt(sa, offsets, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_txt_r(sa, offsets, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_mpag_r(sa, offsets, name, len, S6DNS_T_TXT, &s6dns_message_parse_answer_strings, qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_txt_r_g(sa, offsets, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_txt_r(sa, offsets, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_mx(mxs, name, len, qualif, deadline, stamp) s6dns_resolve_mx_r(mxs, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_mx_g(mxs, name, len, qualif, deadline) s6dns_resolve_mx(mxs, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_mx_r(mxs, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_MX, &s6dns_message_parse_answer_mx, (mxs), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_mx_r_g(mxs, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_mx_r(mxs, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_ns(ds, name, len, qualif, deadline, stamp) s6dns_resolve_ns_r(ds, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_ns_g(ds, name, len, qualif, deadline) s6dns_resolve_ns(ds, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_ns_r(ds, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_dpag_r(ds, name, len, S6DNS_T_NS, qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_ns_r_g(ds, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_ns_r(ds, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_cname(ds, name, len, qualif, deadline, stamp) s6dns_resolve_cname_r(ds, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_cname_g(ds, name, len, qualif, deadline) s6dns_resolve_cname(ds, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_cname_r(ds, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_dpag_r(ds, name, len, S6DNS_T_CNAME, qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_cname_r_g(ds, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_cname_r(ds, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_hinfo(hinfos, name, len, qualif, deadline, stamp) s6dns_resolve_hinfo_r(hinfos, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_hinfo_g(hinfos, name, len, qualif, deadline) s6dns_resolve_hinfo(hinfos, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_hinfo_r(hinfos, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_HINFO, &s6dns_message_parse_answer_hinfo, (hinfos), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_hinfo_r_g(hinfos, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_hinfo_r(hinfos, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_soa(soas, name, len, qualif, deadline, stamp) s6dns_resolve_soa_r(soas, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_soa_g(soas, name, len, qualif, deadline) s6dns_resolve_soa(soas, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_soa_r(soas, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_SOA, &s6dns_message_parse_answer_soa, (soas), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_soa_r_g(soas, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_soa_r(soas, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_srv(srvs, name, len, qualif, deadline, stamp) s6dns_resolve_srv_r(srvs, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_srv_g(srvs, name, len, qualif, deadline) s6dns_resolve_srv(srvs, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_srv_r(srvs, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_SRV, &s6dns_message_parse_answer_srv, (srvs), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_srv_r_g(srvs, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_srv_r(srvs, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_caa(caas, name, len, qualif, deadline, stamp) s6dns_resolve_caa_r(caas, name, len, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_caa_g(caas, name, len, qualif, deadline) s6dns_resolve_caa(caas, name, len, qualif, (deadline), &STAMP)
#define s6dns_resolve_caa_r(caas, name, len, qualif, dt, rci, dbh, deadline, stamp) s6dns_resolve_r(name, len, S6DNS_T_CAA, &s6dns_message_parse_answer_caa, (caas), qualif, dt, rci, dbh, deadline, stamp)
#define s6dns_resolve_caa_r_g(caas, name, len, qualif, dt, rci, dbh, deadline) s6dns_resolve_caa_r(caas, name, len, qualif, dt, rci, dbh, (deadline), &STAMP)


 /* Internals for the high-level functions. */

  /* dpag: structure for generic domain lists + rtype */
  /* mpag: encoding variable-length information into storage+offsets */

#define s6dns_resolve_dpag(ds, name, len, qtype, qualif, deadline, stamp) s6dns_resolve_dpag_r(ds, name, len, qtype, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_dpag_g(ds, name, len, qtype, qualif, deadline) s6dns_resolve_dpag(ds, name, len, qtype, qualif, (deadline), &STAMP)
extern int s6dns_resolve_dpag_r (genalloc *, char const *, unsigned int, uint16_t, int, s6dns_engine_t *, s6dns_rci_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolve_dpag_r_g(ds, name, len, qtype, qualif, dt, rci, dbh, deadline) s6dns_resolve_dpag_r(ds, name, len, qtype, qualif, dt, rci, dbh, (deadline), &STAMP)

#define s6dns_resolve_mpag(sa, offsets, name, len, qtype, parsefunc, qualif, deadline, stamp) s6dns_resolve_mpag_r(sa, offsets, name, len, qtype, parsefunc, qualif, &s6dns_engine_here, &s6dns_rci_here, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolve_mpag_g(sa, offsets, name, len, qtype, parsefunc, qualif, deadline) s6dns_resolve_mpag(sa, offsets, name, len, qtype, parsefunc, qualif, (deadline), &STAMP)
extern int s6dns_resolve_mpag_r (stralloc *, genalloc *, char const *, unsigned int, uint16_t, s6dns_message_rr_func_t_ref, int, s6dns_engine_t *, s6dns_rci_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolve_mpag_r_g(sa, offsets, name, len, qtype, parsefunc, qualif, dt, rci, dbh, deadline) s6dns_resolve_mpag_r(sa, offsets, name, len, qtype, parsefunc, qualif, dt, rci, dbh, (deadline), &STAMP)


 /*
    Functions for n-domain parallel resolution.
    s6dns_resolven_loop() is the core primitive.
    s6dns_resolven_parse() is built upon it.
    This API is still very limited in what it can do; for full
    asynchronous resolution, use the skadns library.
 */

extern int s6dns_resolven_loop (s6dns_engine_t *, unsigned int, unsigned int, tain_t const *, tain_t *) ;
#define s6dns_resolven_loop_g(list, n, zor, deadline) s6dns_resolven(list, n, zor, (deadline), &STAMP)

typedef struct s6dns_resolve_s s6dns_resolve_t, *s6dns_resolve_t_ref ;
struct s6dns_resolve_s
{
  s6dns_domain_t q ;
  tain_t deadline ;
  s6dns_message_rr_func_t_ref parsefunc ;
  void *data ;
  uint32_t options ;
  int status ;
  uint16_t qtype ;
} ;

#define s6dns_resolven_parse(list, n, deadline, stamp) s6dns_resolven_parse_r(list, n, &s6dns_rci_here.servers, &s6dns_debughook_zero, deadline, stamp)
#define s6dns_resolven_parse_g(list, n, deadline) s6dns_resolven_parse(list, n, (deadline), &STAMP)
extern int s6dns_resolven_parse_r (s6dns_resolve_t *, unsigned int, s6dns_ip46list_t const *, s6dns_debughook_t const *, tain_t const *, tain_t *) ;
#define s6dns_resolven_parse_r_g(list, n, servers, dbh, deadline) s6dns_resolven_parse_r(list, n, servers, dbh, (deadline), &STAMP)

#endif
