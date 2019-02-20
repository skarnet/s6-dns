/* ISC license. */

#include <string.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-dns/s6dns-message.h>

int s6dns_message_parse_answer_strings (s6dns_message_rr_t const *rr, char const *packet, unsigned int packetlen, unsigned int pos, unsigned int section, void *stuff)
{
  s6dns_mpag_t *data = stuff ;
  if ((section == 2) && (rr->rtype == data->rtype))
  {
    size_t base = data->sa.len ;
    int wasnull = !data->sa.s ;
    unsigned int start = pos ;
    int r ;
    if (!stralloc_readyplus(&data->sa, rr->rdlength + 1)) return -1 ;
    r = s6dns_message_get_strings(data->sa.s + data->sa.len, rr->rdlength, packet, packetlen, &pos) ;
    if ((r < 0) || (rr->rdlength != pos - start))
    {
      if (wasnull) stralloc_free(&data->sa) ; else data->sa.len = base ;
      return (errno = EPROTO, 0) ;
    }
    if (!genalloc_append(size_t, &data->offsets, &data->sa.len))
    {
      if (wasnull) stralloc_free(&data->sa) ; else data->sa.len = base ;
      return (errno = EPROTO, -1) ;
    }
    data->sa.len += r ;
    stralloc_0(&data->sa) ;
  }
  return 1 ;
}
