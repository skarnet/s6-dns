/* ISC license. */

#ifndef S6DNS_SHIBARI_INTERNAL_H
#define S6DNS_SHIBARI_INTERNAL_H

#include <stdint.h>

#include <skalibs/diuint32.h>
#include <skalibs/genalloc.h>

typedef struct shibari_ip6_s shibari_ip6_t, *shibari_ip6_t_ref ;
struct shibari_ip6_s
{
  uint64_t addr0 ;
  uint64_t addr1 ;
  uint64_t mask0 ;
  uint64_t mask1 ;
} ;

extern int shibari_whitelist_add6 (genalloc *g, char const *, uint16_t) ;
extern int shibari_whitelist_read (char const *, genalloc *, genalloc *) ;
extern int shibari_whitelist_ip4_match (diuint32 const *, size_t, char const *) ;
extern int shibari_whitelist_ip6_match (shibari_ip6_t const *, size_t, char const *) ;

#endif
