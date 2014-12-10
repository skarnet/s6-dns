/* ISC license. */

#ifndef S6DNS_DEBUG_H
#define S6DNS_DEBUG_H

#include <s6-dns/s6dns-engine.h>

extern s6dns_debughook_func_t s6dns_debug_dumpdt_post_recv ;
extern s6dns_debughook_func_t s6dns_debug_dumpdt_pre_send ;
extern s6dns_debughook_func_t s6dns_debug_dumpdt_post_send ;

#define S6DNS_DEBUG_DUMPDT_INIT(gp) { &s6dns_debug_dumpdt_post_recv, &s6dns_debug_dumpdt_pre_send, &s6dns_debug_dumpdt_post_send, (gp) }
extern s6dns_debughook_t const s6dns_debug_dumpdt_stdout ;
extern s6dns_debughook_t const s6dns_debug_dumpdt_stderr ;

#endif
