/* ISC license. */

#ifndef S6DNS_MESSAGE_INTERNAL_H
#define S6DNS_MESSAGE_INTERNAL_H

#include <sys/types.h>

 /* Low-level packet parsing */

extern int s6dns_message_get_string_internal (char *, size_t, char const *, unsigned int, unsigned int *) ;

#endif
