/* ISC license. */

#ifndef S6DNS_MESSAGE_H
#define S6DNS_MESSAGE_H

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <s6-dns/s6dns-domain.h>


 /* Header */

typedef struct s6dns_message_counts_s s6dns_message_counts_t, *s6dns_message_counts_t_ref ;
struct s6dns_message_counts_s
{
  uint16 qd ;
  uint16 an ;
  uint16 ns ;
  uint16 nr ;
} ;

#define S6DNS_MESSAGE_COUNTS_ZERO { .qd = 0, .an = 0, .ns = 0, .nr = 0 }
extern s6dns_message_counts_t const s6dns_message_counts_zero ;

extern void s6dns_message_counts_pack (char *, s6dns_message_counts_t const *) ;
extern void s6dns_message_counts_unpack (char const *, s6dns_message_counts_t *) ;
extern unsigned int s6dns_message_counts_next (s6dns_message_counts_t *) ;

typedef struct s6dns_message_header_s s6dns_message_header_t, *s6dns_message_header_t_ref ;
struct s6dns_message_header_s
{
  uint16 id ;
  unsigned int qr : 1 ;
  unsigned int opcode : 4 ;
  unsigned int aa : 1 ;
  unsigned int tc : 1 ;
  unsigned int rd : 1 ;
  unsigned int ra : 1 ;
  unsigned int z : 3 ;
  unsigned int rcode : 4 ;
  s6dns_message_counts_t counts ;
} ;

#define S6DNS_MESSAGE_HEADER_ZERO { \
  .id = 0, \
  .qr = 0, \
  .opcode = 0, \
  .aa = 0, \
  .tc = 0, \
  .rd = 0, \
  .ra = 0, \
  .z = 0, \
  .rcode = 0, \
  .counts = S6DNS_MESSAGE_COUNTS_ZERO \
}
extern s6dns_message_header_t const s6dns_message_header_zero ;

extern void s6dns_message_header_pack (char *, s6dns_message_header_t const *) ;
extern void s6dns_message_header_unpack (char const *, s6dns_message_header_t *) ;


 /* Specific RR helpers */

extern int s6dns_message_get_string (s6dns_domain_t *, char const *, unsigned int, unsigned int *) ;
extern int s6dns_message_get_strings (char *, unsigned int, char const *, unsigned int, unsigned int *) ;
extern int s6dns_message_get_domain (s6dns_domain_t *, char const *, unsigned int, unsigned int *) ;

typedef struct s6dns_message_rr_hinfo_s s6dns_message_rr_hinfo_t, *s6dns_message_rr_hinfo_t_ref ;
struct s6dns_message_rr_hinfo_s
{
  s6dns_domain_t cpu ;
  s6dns_domain_t os ;
} ;

extern int s6dns_message_get_hinfo (s6dns_message_rr_hinfo_t *, char const *, unsigned int, unsigned int *) ;

typedef struct s6dns_message_rr_mx_s s6dns_message_rr_mx_t, *s6dns_message_rr_mx_t_ref ;
struct s6dns_message_rr_mx_s
{
  uint16 preference ;
  s6dns_domain_t exchange ;
} ;

extern int s6dns_message_get_mx (s6dns_message_rr_mx_t *, char const *, unsigned int, unsigned int *) ;

typedef struct s6dns_message_rr_soa_s s6dns_message_rr_soa_t, *s6dns_message_rr_soa_t_ref ;
struct s6dns_message_rr_soa_s
{
  s6dns_domain_t mname ;
  s6dns_domain_t rname ;
  uint32 serial ;
  uint32 refresh ;
  uint32 retry ;
  uint32 expire ;
  uint32 minimum ;
} ;

extern int s6dns_message_get_soa (s6dns_message_rr_soa_t *, char const *, unsigned int, unsigned int *) ;

typedef struct s6dns_message_rr_srv_s s6dns_message_rr_srv_t, *s6dns_message_rr_srv_t_ref ;
struct s6dns_message_rr_srv_s
{
  uint16 priority ;
  uint16 weight ;
  uint16 port ;
  s6dns_domain_t target ;
} ;

extern int s6dns_message_get_srv (s6dns_message_rr_srv_t *, char const *, unsigned int, unsigned int *) ;


 /* The callback function type: how to parse RRs */

typedef struct s6dns_message_rr_s s6dns_message_rr_t, *s6dns_message_rr_t_ref ;
struct s6dns_message_rr_s
{
  s6dns_domain_t name ;
  uint16 rtype ;
  uint16 rclass ;
  uint32 ttl ;
  uint16 rdlength ;
} ;

typedef int s6dns_message_rr_func_t (s6dns_message_rr_t const *, char const *, unsigned int, unsigned int, unsigned int, void *) ;
typedef s6dns_message_rr_func_t *s6dns_message_rr_func_t_ref ;


 /* mpag: structure to encode several variable-length results */

typedef struct s6dns_mpag_s s6dns_mpag_t, *s6dns_mpag_t_ref ;
struct s6dns_mpag_s
{
  stralloc sa ;
  genalloc offsets ; /* array of unsigned int */
  uint16 rtype ;
} ;
#define S6DNS_MPAG_ZERO { .sa = STRALLOC_ZERO, .offsets = GENALLOC_ZERO, .rtype = 0 }


 /* dpag: structure for domain lists */

typedef struct s6dns_dpag_s s6dns_dpag_t, *s6dns_dpag_t_ref ;
struct s6dns_dpag_s
{
  genalloc ds ; /* array of s6dns_domain_t */
  uint16 rtype ;
} ;
#define S6DNS_DPAG_ZERO { .ds = GENALLOC_ZERO, .rtype = 0 }


extern s6dns_message_rr_func_t s6dns_message_parse_answer_strings ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_domain ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_a ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_aaaa ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_mx ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_hinfo ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_soa ;
extern s6dns_message_rr_func_t s6dns_message_parse_answer_srv ;


 /* The actual parsing function */

extern int s6dns_message_parse (s6dns_message_header_t_ref, char const *, unsigned int, s6dns_message_rr_func_t_ref, void *) ;


 /* Internals of this function, for lower level access */

extern int s6dns_message_parse_init (s6dns_message_header_t *, s6dns_message_counts_t_ref, char const *, unsigned int, unsigned int *) ;
extern unsigned int s6dns_message_parse_skipqd (s6dns_message_counts_t *, char const *, unsigned int, unsigned int *) ;
extern int s6dns_message_parse_getrr (s6dns_message_rr_t_ref, char const *, unsigned int, unsigned int *) ;
extern unsigned int s6dns_message_parse_next (s6dns_message_counts_t *, s6dns_message_rr_t const *, char const *, unsigned int, unsigned int *) ;

#endif
