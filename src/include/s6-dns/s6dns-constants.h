/* ISC license. */

#ifndef S6DNS_CONSTANTS_H
#define S6DNS_CONSTANTS_H

#include <skalibs/ip46.h>

#define S6DNS_MAX_SERVERS 16U

#define S6DNS_C_IN 0x0001U
#define S6DNS_C_ANY 0x00ffU

#define S6DNS_T_A 1U
#define S6DNS_T_NS 2U
#define S6DNS_T_CNAME 5U
#define S6DNS_T_SOA 6U
#define S6DNS_T_PTR 12U
#define S6DNS_T_HINFO 13U
#define S6DNS_T_MX 15U
#define S6DNS_T_TXT 16U
#define S6DNS_T_RP 17U
#define S6DNS_T_SIG 24U
#define S6DNS_T_KEY 25U
#define S6DNS_T_AAAA 28U
#define S6DNS_T_SRV 33U
#define S6DNS_T_AXFR 252U
#define S6DNS_T_ANY 255U
#define S6DNS_T_CAA 257U

#define S6DNS_O_RECURSIVE 0x0001U
#define S6DNS_O_STRICT 0x0002U

#define S6DNS_W_AND 0
#define S6DNS_W_OR 1
#define S6DNS_W_BEST 2

typedef struct s6dns_constants_error_message_s s6dns_constants_error_message_t, *s6dns_constants_error_message_t_ref ;
struct s6dns_constants_error_message_s
{
  int num ;
  char const *string ;
} ;

extern s6dns_constants_error_message_t const *const s6dns_constants_error ;
extern char const *s6dns_constants_error_str (int) ;

#ifdef SKALIBS_IPV6_ENABLED
# define S6DNS_LOCALHOST_IP IP6_LOCAL
#else
# define S6DNS_LOCALHOST_IP "\177\0\0\1"
#endif

#endif
