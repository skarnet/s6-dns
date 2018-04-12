/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <skalibs/uint16.h>
#include <s6-dns/s6dns-fmt.h>

size_t s6dns_fmt_caa (char *s, size_t max, s6dns_message_rr_caa_t const *caa)
{
  size_t len = 0, taglen = strlen(caa->tag), valuelen = strlen(caa->value) ;
  char fmt[UINT16_FMT] ;
  size_t r = uint16_fmt(fmt, (uint16_t)caa->flags) ;
  if (r + taglen + valuelen + 2 > max) return (errno = ENAMETOOLONG, 0) ;
  memcpy(s + len, fmt, r) ;
  len += r ; s[len++] = ' ' ;
  memcpy(s + len, caa->tag, taglen) ;
  len += taglen ; s[len++] = ' ' ;
  memcpy(s + len, caa->value, valuelen) ;
  len += valuelen ;
  return len ;
}
