/* ISC license. */

#include <sys/types.h>
#include <limits.h>
#include <errno.h>
#include <s6-dns/s6dns-domain.h>
#include "s6dns-generic-filter.h"

size_t s6dns_namescanner (s6dns_domain_t *d, char const *s)
{
  register size_t pos = 0 ;
  while (s[pos] && (s[pos] != ' ') && (s[pos] != '\t') && (s[pos] != '\r') && (s[pos] != '\n')) pos++ ;
  if (pos > UINT_MAX) return (errno = ENAMETOOLONG, 0) ;
  if (!s6dns_domain_fromstring_noqualify_encode(d, s, pos)) return 0 ;
  return pos ;
}
