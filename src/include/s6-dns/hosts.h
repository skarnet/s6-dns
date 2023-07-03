/* ISC license. */

#ifndef S6DNS_HOSTS_H
#define S6DNS_HOSTS_H

#include <skalibs/cdb.h>
#include <skalibs/genalloc.h>

extern cdb s6dns_hosts_here ;

extern int s6dns_hosts_init (cdb *) ;
#define s6dns_hosts_free(c) cdb_free(c)

extern int s6dns_hosts_compile (int, int) ;

#endif
