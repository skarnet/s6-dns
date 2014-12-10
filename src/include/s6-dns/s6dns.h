/* ISC license. */

#ifndef S6DNS_H
#define S6DNS_H

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-ip46.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>
#include <s6-dns/s6dns-rci.h>
#include <s6-dns/s6dns-resolve.h>
#include <s6-dns/s6dns-fmt.h>

#define s6dns_init() s6dns_rci_init(&s6dns_rci_here, "/etc/resolv.conf")
#define s6dns_finish() (s6dns_engine_free(&s6dns_engine_here), s6dns_rci_free(&s6dns_rci_here))

#endif
