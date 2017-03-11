/* ISC license. */

#include <string.h>
#include <skalibs/types.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>

size_t s6dns_fmt_mx (char *s, size_t max, s6dns_message_rr_mx_t const *mx)
{
  char fmt[UINT16_FMT] ;
  size_t len = uint16_fmt(fmt, mx->preference) ;
  unsigned int r ;
  if (len >= max) return 0 ;
  fmt[len++] = ' ' ;
  r = s6dns_domain_tostring(s + len, max - len, &mx->exchange) ;
  if (!r) return 0 ;
  memcpy(s, fmt, len) ;
  return len + r ;
}
