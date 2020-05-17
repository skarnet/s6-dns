/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>

int s6dns_message_parse (s6dns_message_header_t *h, char const *packet, unsigned int packetlen, s6dns_message_rr_func_t_ref f, void *data)
{
  s6dns_message_counts_t counts ;
  unsigned int pos ;
  unsigned int section ;
  int gotans ;
  if (!s6dns_message_parse_init(h, &counts, packet, packetlen, &pos)) return 0 ;
  switch (h->rcode)
  {
    case 0 : break ;
    case 1 : return (errno = EILSEQ, 0) ;
    case 2 : return (errno = EBUSY, 0) ;
    case 3 : return (errno = ENOENT, 0) ;
    case 4 : return (errno = ENOTSUP, 0) ;
    case 5 : return (errno = ECONNREFUSED, 0) ;
    default: return (errno = EIO, 0) ;
  }
  gotans = !!counts.an ;
  section = s6dns_message_parse_skipqd(&counts, packet, packetlen, &pos) ;
  while (section)
  {
    s6dns_message_rr_t rr ;
    if (!s6dns_message_parse_getrr(&rr, packet, packetlen, &pos)) return 0 ;
    if (rr.rclass == S6DNS_C_IN)
    {
      int r = (*f)(&rr, packet, packetlen, pos, section, data) ;
      if (r < 1) return r ;
    }
    section = s6dns_message_parse_next(&counts, &rr, packet, packetlen, &pos) ;
  }
  return 1 + gotans ;
}
