/* ISC license. */

#include <stdint.h>
#include <errno.h>
#include <dirent.h>

#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/diuint32.h>
#include <skalibs/genalloc.h>
#include <skalibs/direntry.h>
#include <skalibs/ip46.h>

#include "shibari-internal.h"

static int shibari_whitelist_add4 (genalloc *g, char const *ip4, uint16_t mask)
{
  diuint32 d = { .right = ((uint32_t)1 << mask) - 1 } ;
  uint32_unpack_big(ip4, &d.left) ;
  d.left &= d.right ;
  return genalloc_append(diuint32, g, &d) ;
}

int shibari_whitelist_read (char const *path, genalloc *ip4, genalloc *ip6)
{
  DIR *dir = opendir(path) ;
  if (!dir) return 0 ;
  genalloc_setlen(diuint32, ip4, 0) ;
  genalloc_setlen(shibari_ip6_t, ip6, 0) ;
  for (;;)
  {
    direntry *d ;
    size_t pos ;
    ip46_t ip ;
    uint16_t mask ;
    errno = 0 ;
    d = readdir(dir) ;
    if (!d) break ;
    if (d->d_name[0] == '.' && (!d->d_name[1] || (d->d_name[1] == '.' && !d->d_name[2]))) continue ;
    pos = ip46_scan(d->d_name, &ip) ;
    if (!pos) continue ;
    if (d->d_name[pos] && d->d_name[pos] != '_') continue ;
    if (!d->d_name[pos]) mask = ip46_is6(&ip) ? 128 : 32 ;
    else
    {
      if (!uint160_scan(d->d_name + pos + 1, &mask)) continue ;
      if (mask > (ip46_is6(&ip) ? 128 : 32)) continue ;
    }
    if (!(ip46_is6(&ip) ? shibari_whitelist_add6(ip6, ip.ip, mask) : shibari_whitelist_add4(ip4, ip.ip, mask))) goto err ;
  }
  if (errno) goto err ;
  dir_close(dir) ;
  return 1 ;

 err:
  dir_close(dir) ;
  return 0 ;
}
