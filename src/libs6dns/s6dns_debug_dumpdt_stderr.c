/* ISC license */

#include <skalibs/genwrite.h>
#include <s6-dns/s6dns-debug.h>

s6dns_debughook_t const s6dns_debug_dumpdt_stderr = S6DNS_DEBUG_DUMPDT_INIT((void *)&genwrite_stderr) ;
