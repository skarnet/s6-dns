/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>

size_t s6dns_fmt_hinfo (char *s, size_t max, s6dns_message_rr_hinfo_t const *hinfo)
{
  if (hinfo->cpu.len + 1 + hinfo->os.len > max) return (errno = ENAMETOOLONG, 0) ;
  byte_copy(s, hinfo->cpu.len, hinfo->cpu.s) ;
  s[hinfo->cpu.len] = ' ' ;
  byte_copy(s + hinfo->cpu.len + 1, hinfo->os.len, hinfo->os.s) ;
  return hinfo->cpu.len + 1 + hinfo->os.len ;
}
