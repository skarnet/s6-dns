/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/types.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-domain.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-analyze.h>

#define add(s) if ((*gp->put)(gp->target, (s), strlen(s)) < 0) return 0
#define addfmt(n) if ((*gp->put)(gp->target, fmt, uint_fmt(fmt, (n))) < 0) return 0
#define addfmt16(n) if ((*gp->put)(gp->target, fmt, uint16_fmt(fmt, (n))) < 0) return 0

int s6dns_analyze_packet (genwrite *gp, char const *packet, unsigned int packetlen, int rec)
{
  s6dns_message_header_t h ;
  s6dns_message_counts_t counts ;
  unsigned int pos ;
  unsigned int section ;
  char fmt[UINT_FMT] ;
  if (!s6dns_message_parse_init(&h, &counts, packet, packetlen, &pos))
    return 0 ;

  addfmt(packetlen) ;
  add(" bytes, ") ;
  addfmt16(counts.qd) ;
  add("+") ;
  addfmt16(counts.an) ;
  add("+") ;
  addfmt16(counts.ns) ;
  add("+") ;
  addfmt16(counts.nr) ;
  add(" records") ;
  if (h.qr) add(", response") ;
  if (h.opcode)
  {
    add(", weird op (") ;
    addfmt(h.opcode) ;
    add(")") ;
  }
  if (h.aa) add(", authoritative") ;
  if (h.tc) add(", truncated") ;
  if (h.rd)
  {
    add(", ") ;
    if (!rec) add("weird ") ;
    add("rd") ;
  }
  if (h.ra)
  {
    add(", ") ;
    if (!rec) add("weird ") ;
    add("ra") ;
  }
  switch (h.rcode)
  {
    case 0 : add(", noerror") ; break ;
    case 1 : add(", fmterror") ; break ;
    case 2 : add(", servfail") ; break ;
    case 3 : add(", nxdomain") ; break ;
    case 4 : add(", notimpl") ; break ;
    case 5 : add(", refused") ; break ;
    default:
    {
      add(", weird rcode (") ;
      addfmt(h.rcode) ;
      add(")") ;
    }
  }
  if (h.z)
  {
    add(", weird z (") ;
    addfmt(h.z) ;
    add(")") ;
  }
  add("\n") ;

  for (;;)
  {
    s6dns_domain_t d ;
    char buf[257] ;
    unsigned int len ;
    uint16_t qtype ;
    uint16_t qclass ;
    section = s6dns_message_counts_next(&counts) ;
    if (section != 1) break ;
    add("query: ") ;
    if (!s6dns_message_get_domain(&d, packet, packetlen, &pos)) return 0 ;
    len = s6dns_domain_tostring(buf, 255, &d) ;
    if (!len) return 0 ;
    buf[len++] = '\n' ; buf[len++] = 0 ;
    if (pos + 4 > packetlen) return (errno = EPROTO, 0) ;
    uint16_unpack_big(packet + pos, &qtype) ; pos += 2 ;
    uint16_unpack_big(packet + pos, &qclass) ; pos += 2 ;
    if (qclass != S6DNS_C_IN)
    {
      add("weird class (") ;
      addfmt16(qclass) ;
      add(") - ") ;
    }
    addfmt16(qtype) ;
    add(" ") ;
    add(buf) ;
  }

  while (section)
  {
    static char const *intro[3] = { "answer: ", "authority: ", "additional: " } ;
    s6dns_message_rr_t rr ;
    if (!s6dns_message_parse_getrr(&rr, packet, packetlen, &pos)) return 0 ;
    add(intro[section-2]) ;
    if (rr.rclass != S6DNS_C_IN)
    {
      add("weird class (") ;
      addfmt16(rr.rclass) ;
      add("), not attempting to analyze record\n") ;
    }
    else if (!s6dns_analyze_record(gp, &rr, packet, packetlen, pos)) return 0 ;
    section = s6dns_message_parse_next(&counts, &rr, packet, packetlen, &pos) ;
  }

  return 1 ;
}
