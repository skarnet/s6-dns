/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/posixishard.h>

#include <s6-dns/s6dns-message.h>

size_t s6dns_message_get_domain_nodecode (char *out, size_t outmax, char const *s, unsigned int len, unsigned int *pos)
{
  size_t w = 0 ; /* writing head */
  unsigned int r = *pos ; /* reading head */
  unsigned int jumps = 0 ;
  int hasjumped = 0 ;
  for (;;)
  {
    unsigned char c ;
    if (r >= len) return (errno = EPROTO, 0) ;
    c = s[r] ;
    if (c < 64) /* normal label */
    {
      if (r + ++c > len) return (errno = EPROTO, 0) ;
      if (out)
      {
        if (w + c > outmax) return (errno = ENAMETOOLONG, 0) ;
        memcpy(out + w, s + r, c) ;
      }
      w += c ; r += c ; if (!hasjumped) *pos += c ;
      if (c == 1) break ;
    }
    else if (c >= 192) /* pointer */
    {
      if (r + 1 >= len) return (errno = EPROTO, 0) ;
      if (hasjumped)
      {
        if (++jumps > 1000) return (errno = EPROTO, 0) ;
      }
      else
      {
        *pos += 2 ;
        hasjumped = 1 ;
      }
      r = (((unsigned int)c & 63) << 8) | (unsigned char)(s[r + 1]) ;
    }
    else return (errno = EPROTONOSUPPORT, 0) ; /* unsupported extension */
  }
  return w ;
}
