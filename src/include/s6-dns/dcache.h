/* ISC license. */

#ifndef S6DNS_DCACHE_H
#define S6DNS_DCACHE_H

#include <stdint.h>

#include <skalibs/uint64.h>
#include <skalibs/tai.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>

#define DCACHE_MAGIC "--DCACHE--\n"

typedef struct dcache_key_s dcache_key_t, *dcache_key_t_ref ;
struct dcache_key_s
{
  char *s ;
  uint16_t len ;
} ;

typedef struct dcache_node_s dcache_node_t, *dcache_node_t_ref ;
struct dcache_node_s
{
  dcache_key_t key ;
  uint16_t datalen ;
  tain_t entry ;
  tain_t expire ;
} ;

typedef struct dcache_s dcache_t, *dcache_t_ref ;
struct dcache_s
{
  gensetdyn storage ; /* dcache_node_t */
  avltree by_key ;
  avltree by_entry ;
  avltree by_expire ;
  uint64_t size ;
  uint64_t motion ;
} ;
#define DCACHE_ZERO { .storage = GENSETDYN_ZERO, .by_key = AVLTREE_ZERO, .by_entry = AVLTREE_ZERO, .by_expire = AVLTREE_ZERO, .size = 0, .motion = 0 }

extern void dcache_init (dcache_t *, uint64_t) ;
extern dcache_node_t *dcache_search (dcache_t *, char const *, uint16_t) ;
extern int dcache_add (dcache_t *, uint64_t, char const *, uint16_t, char const *, uint16_t, tain_t const *, tain_t const *) ;
#define dcache_add_g(d, max, key, keylen, data, datalen, expire) dcache_add(d, max, key, keylen, data, datalen, (expire), &STAMP)
extern void dcache_clean_expired (dcache_t *, tain_t const *) ;
#define dcache_clean_expired_g(d) dcache_clean_expired((d), &STAMP)
extern void dcache_free (dcache_t *) ;

extern int dcache_save (dcache_t const *, char const *) ;
extern int dcache_load (dcache_t *, uint64_t, char const *) ;

#endif
