/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/uio.h>

#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>
#include <skalibs/cdbmake.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/gensetdyn.h>
#include <skalibs/avltree.h>
#include <skalibs/lolstdio.h>

#include <s6-dns/hosts.h>


 /* Definitions */

typedef struct node_name_s node_name, *node_name_ref ;
struct node_name_s
{
  size_t pos ;
  stralloc ipv4 ;
  stralloc ipv6 ;
} ;

typedef struct node_ip_s node_ip, *node_ip_ref ;
struct node_ip_s
{
  char addr[16] ;
  genalloc names ; /* size_t */
} ;

typedef struct hostdata_s hostdata, *hostdata_ref ;
struct hostdata_s
{
  stralloc storage ;
  gensetdyn alias ;
  gensetdyn fqdn ;
  gensetdyn ipv4 ;
  gensetdyn ipv6 ;
  avltree byalias ;
  avltree byfqdn ;
  avltree byipv4 ;
  avltree byipv6 ;
} ;
#define HOSTDATA_ZERO \
{ \
  .storage = STRALLOC_ZERO, \
  .alias = GENSETDYN_INIT(node_name, 3, 3, 8), \
  .fqdn = GENSETDYN_INIT(node_name, 3, 3, 8), \
  .ipv4 = GENSETDYN_INIT(node_ip, 3, 3, 8), \
  .ipv6 = GENSETDYN_INIT(node_ip, 3, 3, 8), \
  .byalias = AVLTREE_ZERO, \
  .byfqdn = AVLTREE_ZERO, \
  .byipv4 = AVLTREE_ZERO, \
  .byipv6 = AVLTREE_ZERO \
}

typedef struct hdcm_s hdcm, *hdcm_ref ;
struct hdcm_s
{
  hostdata *hd ;
  cdbmaker *cm ;
  char key[2] ;
} ;


 /* Utility */

static void node_name_free (void *data)
{
  node_name *node = data ;
  stralloc_free(&node->ipv4) ;
  stralloc_free(&node->ipv6) ;
}

static void node_ip_free (void *data)
{
  node_ip *node = data ;
  genalloc_free(size_t, &node->names) ;
}

static void hostdata_free (hostdata *hd)
{
  gensetdyn_deepfree(&hd->alias, &node_name_free) ;
  gensetdyn_deepfree(&hd->fqdn, &node_name_free) ;
  gensetdyn_deepfree(&hd->ipv4, &node_ip_free) ;
  gensetdyn_deepfree(&hd->ipv6, &node_ip_free) ;
  avltree_free(&hd->byalias) ;
  avltree_free(&hd->byfqdn) ;
  avltree_free(&hd->byipv4) ;
  avltree_free(&hd->byipv6) ;
  stralloc_free(&hd->storage) ;
}

static int name_cmp (void const *a, void const *b, void *aux)
{
  (void)aux ;
  return strcmp((char const *)a, (char const *)b) ;
}

static void *byalias_dtok (uint32_t d, void *aux)
{
  hostdata *hd = aux ;
  return hd->storage.s + GENSETDYN_P(node_name, &hd->alias, d)->pos ;
}

static void *byfqdn_dtok (uint32_t d, void *aux)
{
  hostdata *hd = aux ;
  return hd->storage.s + GENSETDYN_P(node_name, &hd->fqdn, d)->pos ;
}

static int ipv4_cmp (void const *a, void const *b, void *aux)
{
  (void)aux ;
  return memcmp((char const *)a, (char const *)b, 4) ;
}

static void *byipv4_dtok (uint32_t d, void *aux)
{
  hostdata *hd = aux ;
  return GENSETDYN_P(node_ip, &hd->ipv4, d)->addr ;
}

static int ipv6_cmp (void const *a, void const *b, void *aux)
{
  (void)aux ;
  return memcmp((char const *)a, (char const *)b, 16) ;
}

static void *byipv6_dtok (uint32_t d, void *aux)
{
  hostdata *hd = aux ;
  return GENSETDYN_P(node_ip, &hd->ipv6, d)->addr ;
}


 /* Reading */

static inline uint8_t cclass (char c)
{
  static uint8_t const ctable[128] = "09999999913111999999999999999999199999999999945977777777776999999888888888888888888888888889999898888888888888888888888888899999" ;
  return c & 0x80 ? 9 : ctable[(uint8_t)c] - '0' ;
}

static inline char next (buffer *b)
{
  char c ;
  return buffer_get(b, &c, 1) <= 0 ? 0 : c ;
}

static int s6dns_hosts_parse (buffer *b, hostdata *hd)
{
  static uint8_t const table[6][10] =
  {
    { 0x06, 0x00, 0x01, 0x00, 0x07, 0x07, 0x0a, 0x0a, 0x0a, 0x07 },
    { 0x06, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
    { 0x16, 0x13, 0x07, 0x10, 0x07, 0x0a, 0x0a, 0x0a, 0x0a, 0x07 },
    { 0x06, 0x03, 0x01, 0x00, 0x07, 0x07, 0x07, 0x07, 0x0c, 0x07 },
    { 0x26, 0x64, 0x07, 0x20, 0x0c, 0x0c, 0x07, 0x0c, 0x0c, 0x07 },
    { 0x06, 0x05, 0x01, 0x00, 0x07, 0x07, 0x07, 0x07, 0x0c, 0x07 }
  } ;
  node_ip *node = 0 ;
  size_t mark = hd->storage.len ;
  uint8_t flags = 0 ;
  uint8_t state = 0 ;
  while (state < 0x06)
  {
    uint8_t c ;
    char cur ;
    ssize_t r = buffer_get(b, &cur, 1) ;
    if (r == -1) goto err ;
    if (!r) cur = 0 ;
    c = table[state][cclass(cur)] ;
    LOLDEBUG("parse: state: %hhu, event: %c, newstate: %hhu, actions: %s%s%s%s", state, cur, c & 0x07, c & 0x08 ? "p" : "", c & 0x10 ? "s" : "", c & 0x20 ? "f" : "", c & 0x40 ? "n" : "") ;
    state = c & 0x07 ;
    if (c & 0x08) if (!stralloc_catb(&hd->storage, &cur, 1)) goto err ;
    if (c & 0x10)
    {
      char ip[16] ;
      if (!stralloc_0(&hd->storage)) goto err ;
      if (ip6_scan(hd->storage.s + mark, ip))
      {
        uint32_t d ;
#ifdef DEBUG
        LOLDEBUG("parse: ipv6 found: %s", hd->storage.s + mark) ;
#endif
        if (!avltree_search(&hd->byipv6, ip, &d))
        {
          if (!gensetdyn_new(&hd->ipv6, &d)) goto err ;
          memcpy(GENSETDYN_P(node_ip, &hd->ipv6, d)->addr, ip, 16) ;
          GENSETDYN_P(node_ip, &hd->ipv6, d)->names = genalloc_zero ;
          if (!avltree_insert(&hd->byipv6, d)) goto err ;
        }
        flags |= 1 ;
        node = GENSETDYN_P(node_ip, &hd->ipv6, d) ;
      }
      else if (ip4_scan(hd->storage.s + mark, ip))
      {
#ifdef DEBUG
        LOLDEBUG("parse: ipv4 found: %s", hd->storage.s + mark) ;
#endif
        uint32_t d ;
        if (!avltree_search(&hd->byipv4, ip, &d))
        {
          if (!gensetdyn_new(&hd->ipv4, &d)) goto err ;
          memcpy(GENSETDYN_P(node_ip, &hd->ipv4, d)->addr, ip, 4) ;
          GENSETDYN_P(node_ip, &hd->ipv4, d)->names = genalloc_zero ;
          if (!avltree_insert(&hd->byipv4, d)) goto err ;
        }
        flags &= ~1 ;
        node = GENSETDYN_P(node_ip, &hd->ipv4, d) ;
      }
      else goto err ;
      LOLDEBUG("parse: %s has %zu names so far", hd->storage.s + mark, genalloc_len(size_t, &node->names)) ;
      hd->storage.len = mark ;
      flags &= ~2 ;
    }
    if (c & 0x20)
    {
      node_name *noden ;
      size_t i = 0 ;
      if (flags & 2)
      {
        uint32_t d ;
        if (!stralloc_0(&hd->storage)) goto err ;
        LOLDEBUG("parse: alias found: %s", hd->storage.s + mark) ;
        if (!avltree_search(&hd->byalias, hd->storage.s + mark, &d))
        {
          if (!gensetdyn_new(&hd->alias, &d)) goto err ;
          GENSETDYN_P(node_name, &hd->alias, d)->pos = mark ;
          GENSETDYN_P(node_name, &hd->alias, d)->ipv4 = stralloc_zero ;
          GENSETDYN_P(node_name, &hd->alias, d)->ipv6 = stralloc_zero ;
          if (!avltree_insert(&hd->byalias, d)) goto err ;
        }
        else hd->storage.len = mark ;
        noden = GENSETDYN_P(node_name, &hd->alias, d) ;
      }
      else
      {
        uint32_t d ;
        if (!stralloc_catb(&hd->storage, ".", 2)) goto err ;
        LOLDEBUG("parse: fqdn found: %s", hd->storage.s + mark) ;
        if (!avltree_search(&hd->byfqdn, hd->storage.s + mark, &d))
        {
          if (!gensetdyn_new(&hd->fqdn, &d)) goto err ;
          GENSETDYN_P(node_name, &hd->fqdn, d)->pos = mark ;
          GENSETDYN_P(node_name, &hd->fqdn, d)->ipv4 = stralloc_zero ;
          GENSETDYN_P(node_name, &hd->fqdn, d)->ipv6 = stralloc_zero ;
          if (!avltree_insert(&hd->byfqdn, d)) goto err ;
        }
        else hd->storage.len = mark ;
        noden = GENSETDYN_P(node_name, &hd->fqdn, d) ;
      }
      LOLDEBUG("parse: %s has %zu ipv4 and %zu ipv6 so far", hd->storage.s + noden->pos, noden->ipv4.len >> 2, noden->ipv6.len >> 4) ;
      for (; i < genalloc_len(size_t, &node->names) ; i++)
        if (!strcmp(hd->storage.s + noden->pos, hd->storage.s + genalloc_s(size_t, &node->names)[i])) break ;
      if (i >= genalloc_len(size_t, &node->names))
      {
        LOLDEBUG("parse: adding it to current ipv%s", flags & 1 ? "6" : "4") ;
        if (!genalloc_catb(size_t, &node->names, &noden->pos, 1)) goto err ;
      }
      if (flags & 1)
      {
        for (i = 0 ; i < noden->ipv6.len ; i += 16)
          if (!memcmp(node->addr, noden->ipv6.s + i, 16)) break ;
        if (i >= noden->ipv6.len)
        {
          LOLDEBUG("parse: adding current ipv6 to address list for %s", hd->storage.s + noden->pos) ;
          if (!stralloc_catb(&noden->ipv6, node->addr, 16)) goto err ;
        }
      }
      else
      {
        for (i = 0 ; i < noden->ipv4.len ; i += 4)
          if (!memcmp(node->addr, noden->ipv4.s + i, 4)) break ;
        if (i >= noden->ipv4.len)
        {
          LOLDEBUG("parse: adding current ipv4 to address list for %s", hd->storage.s + noden->pos) ;
          if (!stralloc_catb(&noden->ipv4, node->addr, 4)) goto err ;
        }
      }
      mark = hd->storage.len ;
    }
    if (c & 0x40) flags |= 2 ;
  }
  if (state > 0x06) return (errno = EILSEQ, 0) ;
  return 1 ;

 err:
  hostdata_free(hd) ;
  return 0 ;
}

 /* Writing */

static int name_write_iter (void *data, void *aux)
{
  node_name *node = data ;
  hdcm *blah = aux ;
  char keybase[4] = "q4:" ;
  struct iovec kv[2] = { { .iov_base = keybase, .iov_len = 3 }, { .iov_base = blah->hd->storage.s + node->pos, .iov_len = strlen(blah->hd->storage.s + node->pos) + 1 } } ;
  struct iovec dv = { .iov_base = node->ipv4.s, .iov_len = node->ipv4.len } ;
  LOLDEBUG("name_write_iter: name: %s, ipv4.len: %u, ipv6.len: %u", blah->hd->storage.s + node->pos, (unsigned int)node->ipv4.len, (unsigned int)node->ipv6.len) ;
  if (node->ipv4.len && !cdbmake_addv(blah->cm, kv, 2, &dv, 1)) return 0 ;
  if (node->ipv6.len)
  {
    keybase[1] = '6' ;
    dv.iov_base = node->ipv6.s ; dv.iov_len = node->ipv6.len ;
    if (!cdbmake_addv(blah->cm, kv, 2, &dv, 1)) return 0 ;
  }
  return 1 ;
}

static int ip_write_iter (void *data, void *aux)
{
  node_ip *node = data ;
  hdcm *blah = aux ;
  size_t n = genalloc_len(size_t, &node->names) ;
#ifdef DEBUG
  {
    char fmt[IP6_FMT] ;
    if (blah->key[1] == '6') fmt[ip6_fmt(fmt, node->addr)] = 0 ;
    else fmt[ip4_fmt(fmt, node->addr)] = 0 ;
    LOLDEBUG("ip_write_iter: %s: names: %u", fmt, (unsigned int)n) ;
  }
#endif
  if (n)
  {
    size_t const *p = genalloc_s(size_t, &node->names) ;
    struct iovec kv[3] = { { .iov_base = blah->key, .iov_len = 2 }, { .iov_base = ":", .iov_len = 1 }, { .iov_base = node->addr, .iov_len = blah->key[1] == '6' ? 16 : 4 } } ;
    struct iovec dv[n] ;
    for (size_t i = 0 ; i < n ; i++)
    {
      dv[i].iov_base = blah->hd->storage.s + p[i] ;
      dv[i].iov_len = strlen(blah->hd->storage.s + p[i]) + 1 ;
    }
    if (!cdbmake_addv(blah->cm, kv, 3, dv, n)) return 0 ;
  }
  return 1 ;
}

static int s6dns_hosts_write (hostdata *hd, cdbmaker *cm)
{
  hdcm blah = { .hd = hd, .cm = cm, .key = { 'q', '4' } } ;
  LOLDEBUG("writing alias") ;
  if (gensetdyn_iter(&hd->alias, &name_write_iter, &blah) < gensetdyn_n(&hd->alias)) return 0 ;
  blah.key[0] = 'a' ;
  LOLDEBUG("writing fqdn") ;
  if (gensetdyn_iter(&hd->fqdn, &name_write_iter, &blah) < gensetdyn_n(&hd->fqdn)) return 0 ;
  blah.key[0] = 'p' ;
  LOLDEBUG("writing ipv4") ;
  if (gensetdyn_iter(&hd->ipv4, &ip_write_iter, &blah) < gensetdyn_n(&hd->ipv4)) return 0 ;
  blah.key[1] = '6' ;
  LOLDEBUG("writing ipv6") ;
  if (gensetdyn_iter(&hd->ipv6, &ip_write_iter, &blah) < gensetdyn_n(&hd->ipv6)) return 0 ;
  return 1 ;
}


 /* Capstone */

int s6dns_hosts_compile (int fdr, int fdw)
{
  hostdata hd = HOSTDATA_ZERO ;
  {
    char buf[BUFFER_INSIZE] ;
    buffer b = BUFFER_INIT(&buffer_read, fdr, buf, BUFFER_INSIZE) ;
    avltree_init(&hd.byalias, 3, 3, 8, &byalias_dtok, &name_cmp, &hd) ;
    avltree_init(&hd.byfqdn, 3, 3, 8, &byfqdn_dtok, &name_cmp, &hd) ;
    avltree_init(&hd.byipv4, 3, 3, 8, &byipv4_dtok, &ipv4_cmp, &hd) ;
    avltree_init(&hd.byipv6, 3, 3, 8, &byipv6_dtok, &ipv6_cmp, &hd) ;
    if (!s6dns_hosts_parse(&b, &hd)) return 0 ;
  }
  {
    cdbmaker cm = CDBMAKER_ZERO ;
    if (!cdbmake_start(&cm, fdw)) goto err ;
    if (!s6dns_hosts_write(&hd, &cm)) goto err ;
    if (!cdbmake_finish(&cm)) goto err ;
  }
  hostdata_free(&hd) ;
  return 1 ;

 err:
  hostdata_free(&hd) ;
  return 0 ;
}
