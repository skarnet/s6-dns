/* ISC license. */

#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>

#include <s6-dns/s6dns.h>

#define USAGE "shibari [ -m max ] [ -i ipsend ] [ [ -u uid ] [ -g gid ] | [ -U ] ]"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  return 0 ;
}
