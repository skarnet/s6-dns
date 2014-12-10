/* ISC license. */

#include <skalibs/stralloc.h>
#include <s6-dns/s6dns-rci.h>

void s6dns_rci_free (s6dns_rci_t *rci)
{
  stralloc_free(&rci->rules) ;
  *rci = s6dns_rci_zero ;
}
