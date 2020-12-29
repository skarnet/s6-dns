/* ISC license. */

#ifndef S6DNS_DCACHE_INTERNAL_H
#define S6DNS_DCACHE_INTERNAL_H

#include <stdint.h>

#include <skalibs/avlnode.h>
#include <skalibs/gensetdyn.h>

#include <s6-dns/dcache.h>

#define DNODE(z, i) GENSETDYN_P(dcache_node_t, &(z)->storage, i)
#define DCACHE_NODE_OVERHEAD (32 + sizeof(dcache_node_t) + 3 * sizeof(avlnode))

extern void dcache_delete (dcache_t *, uint32_t) ;

#endif
