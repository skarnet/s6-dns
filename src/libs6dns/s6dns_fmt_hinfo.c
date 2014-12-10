/* ISC license. */

#include <errno.h>
#include <skalibs/bytestr.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-fmt.h>

unsigned int s6dns_fmt_hinfo (char *s, unsigned int max, s6dns_message_rr_hinfo_t const *hinfo)
{
  if ((unsigned int)hinfo->cpu.len + 1 + (unsigned int)hinfo->os.len > max) return (errno = ENAMETOOLONG, 0) ;
  byte_copy(s, hinfo->cpu.len, hinfo->cpu.s) ;
  s[hinfo->cpu.len] = ' ' ;
  byte_copy(s + hinfo->cpu.len + 1, hinfo->os.len, hinfo->os.s) ;
  return hinfo->cpu.len + 1 + hinfo->os.len ;
}
