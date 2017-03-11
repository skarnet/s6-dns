/* ISC license. */

#include <string.h>
#include <errno.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>

size_t s6dns_fmt_hinfo (char *s, size_t max, s6dns_message_rr_hinfo_t const *hinfo)
{
  if (hinfo->cpu.len + 1 + hinfo->os.len > max) return (errno = ENAMETOOLONG, 0) ;
  memcpy(s, hinfo->cpu.s, hinfo->cpu.len) ;
  s[hinfo->cpu.len] = ' ' ;
  memcpy(s + hinfo->cpu.len + 1, hinfo->os.s, hinfo->os.len) ;
  return hinfo->cpu.len + 1 + hinfo->os.len ;
}
