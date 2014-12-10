/* ISC license. */

#ifndef S6DNS_IP46_H
#define S6DNS_IP46_H

#include <skalibs/bitarray.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns-constants.h>

typedef struct s6dns_ip46list_s s6dns_ip46list_t, *s6dns_ip46list_t_ref ;
struct s6dns_ip46list_s
{
  char ip[S6DNS_MAX_SERVERS * SKALIBS_IP_SIZE] ;
#ifdef SKALIBS_IPV6_ENABLED
  unsigned char is6[bitarray_div8(S6DNS_MAX_SERVERS)] ;
#endif
} ;

#define s6dns_ip46list_ip(list, i) ((list)->ip + SKALIBS_IP_SIZE * (i))

#ifdef SKALIBS_IPV6_ENABLED
# define S6DNS_IP46LIST_ZERO { .ip = S6DNS_LOCALHOST_IP, .is6 = "\0" }
# define s6dns_ip46list_is6(list, i) bitarray_peek((list)->is6, i)
#else
# define S6DNS_IP46LIST_ZERO { .ip = S6DNS_LOCALHOST_IP }
# define s6dns_ip46list_is6(list, i) 0
#endif
    
#endif    
