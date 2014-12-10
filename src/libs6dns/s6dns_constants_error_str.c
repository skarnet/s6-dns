/* ISC license. */

#include <skalibs/error.h>
#include <s6-dns/s6dns-constants.h>

char const *s6dns_constants_error_str (int e)
{
  s6dns_constants_error_message_t const *p = s6dns_constants_error ;
  while ((p->num != e) && (p->num != -1)) p++ ;
  return p->num == -1 ? error_str(e) : p->string ;
}
