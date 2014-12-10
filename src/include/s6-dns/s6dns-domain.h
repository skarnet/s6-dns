/* ISC license. */

#ifndef S6DNS_DOMAIN_H
#define S6DNS_DOMAIN_H

#include <skalibs/ip46.h>

typedef struct s6dns_domain_s s6dns_domain_t, *s6dns_domain_t_ref ;
struct s6dns_domain_s
{
  unsigned char len ;
  char s[255] ;
} ;


 /* Conversions from/to user strings */

extern int s6dns_domain_fromstring (s6dns_domain_t_ref, char const *, unsigned int) ;
extern unsigned int s6dns_domain_tostring (char *, unsigned int, s6dns_domain_t const *) ;


 /* Qualification */

extern int s6dns_domain_noqualify (s6dns_domain_t_ref) ;
extern unsigned int s6dns_domain_qualify (s6dns_domain_t *, s6dns_domain_t const *, char const *, unsigned int) ;


 /* Internal coding/encoding to/from protocol form */

extern int s6dns_domain_encode (s6dns_domain_t_ref) ;
extern unsigned int s6dns_domain_encodelist (s6dns_domain_t_ref, unsigned int) ;
extern int s6dns_domain_decode (s6dns_domain_t_ref) ;


 /* Useful shortcuts */

extern int s6dns_domain_fromstring_noqualify_encode (s6dns_domain_t_ref, char const *, unsigned int) ;
extern unsigned int s6dns_domain_fromstring_qualify_encode (s6dns_domain_t *, char const *, unsigned int, char const *, unsigned int) ;


 /* Helpers for PTR */

extern void s6dns_domain_arpafromip4 (s6dns_domain_t_ref, char const *) ;
extern void s6dns_domain_arpafromip6 (s6dns_domain_t_ref, char const *, unsigned int) ;
#define s6dns_domain_arpafromip46(d, i) (ip46_is6(i) ? s6dns_domain_arpafromip6(d, (i)->ip, 128) : s6dns_domain_arpafromip4(d, (i)->ip))

#endif
