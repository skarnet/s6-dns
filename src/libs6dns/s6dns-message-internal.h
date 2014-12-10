/* ISC license. */

#ifndef S6DNS_MESSAGE_INTERNAL_H
#define S6DNS_MESSAGE_INTERNAL_H


 /* Low-level packet parsing */

extern int s6dns_message_get_string_internal (char *, unsigned int, char const *, unsigned int, unsigned int *) ;
extern unsigned int s6dns_message_get_domain_internal (char *, unsigned int, char const *, unsigned int, unsigned int *) ;

#endif
