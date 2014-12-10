/* ISC license. */

#include <skalibs/uint16.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>

unsigned int s6dns_fmt_mx (char *s, unsigned int max, s6dns_message_rr_mx_t const *mx)
{
  char fmt[UINT16_FMT] ;
  unsigned int len = uint16_fmt(fmt, mx->preference) ;
  unsigned int r ;
  if (len >= max) return 0 ;
  fmt[len++] = ' ' ;
  r = s6dns_domain_tostring(s + len, max - len, &mx->exchange) ;
  if (!r) return 0 ;
  byte_copy(s, len, fmt) ;
  return len + r ;
}
