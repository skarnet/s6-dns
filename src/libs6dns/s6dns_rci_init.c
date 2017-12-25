/* ISC license. */

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <skalibs/error.h>
#include <skalibs/bytestr.h>
#include <skalibs/bitarray.h>
#include <skalibs/fmtscan.h>
#include <skalibs/djbunix.h>
#include <skalibs/stralloc.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-rci.h>

static size_t readit (char const *file, char *buf, size_t max)
{
  ssize_t r = openreadnclose(file, buf, max - 1) ;
  if (r < 0)
  {
    if (errno != ENOENT) return 0 ;
    else r = 0 ;
  }
  buf[r++] = '\n' ;
  return r ;
}

static inline int s6dns_rci_init_servers (s6dns_rci_t *rci, char const *file, char *tmp, size_t max, size_t *size)
{
  ip46_t tmplist[S6DNS_MAX_SERVERS] ;
  size_t num = 0 ;
  char const *x = getenv("DNSCACHEIP") ;
  if (x) ip46_scanlist(tmplist, S6DNS_MAX_SERVERS, x, &num) ;
  if (!num)
  {
    size_t i = 0 ;
    *size = readit(file, tmp, max) ;
    if (!*size) return 0 ;
    while ((i < *size) && (num < S6DNS_MAX_SERVERS))
    {
      size_t j = byte_chr(tmp + i, *size - i, '\n') ;
      if ((i + j < *size) && (j > 13U) && !memcmp("nameserver", tmp + i, 10))
      {
        size_t k = 0 ;
        while ((tmp[i+10+k] == ' ') || (tmp[i+10+k] == '\t')) k++ ;
        if (k && ip46_scan(tmp+i+10+k, tmplist + num)) num++ ;
      }
      i += j + 1 ;
    }
  }
  if (!num)
  {
    num = 1 ;
    memcpy(tmplist[0].ip, S6DNS_LOCALHOST_IP, SKALIBS_IP_SIZE) ;
#ifdef SKALIBS_IPV6_ENABLED
    tmplist[0].is6 = 1 ;
#endif
  }

  {
    unsigned int i = 0 ;
    memset(&rci->servers, 0, sizeof(s6dns_ip46list_t)) ;
    for (; i < num ; i++)
    {
      memcpy(rci->servers.ip + SKALIBS_IP_SIZE * i, tmplist[i].ip, SKALIBS_IP_SIZE) ;
#ifdef SKALIBS_IPV6_ENABLED
      if (ip46_is6(tmplist+i)) bitarray_set(rci->servers.is6, i) ;
#endif
    }
  }
  return 1 ;
}

static inline int stringrules (stralloc *rules, char const *s, unsigned int *num)
{
  size_t base = rules->len ;
  int wasnull = !rules->s ;
  unsigned int n = 0 ;
  int crunching = 1 ;
  char c = ' ' ;
  while (c)
  {
    c = *s++ ;
    if (memchr(" \t\n\r", c, 5))
    {
      if (!crunching)
      {
        if ((rules->s[rules->len - 1] != '.') && !stralloc_catb(rules, ".", 1)) goto err ;
        if (!stralloc_0(rules)) goto err ;
        n++ ;
        crunching = 1 ;
      }
    }
    else
    {
      if (crunching) crunching = 0 ;
      if (!stralloc_catb(rules, &c, 1)) goto err ;
    }
  }
  *num += n ;
  return 1 ;

 err:
  if (wasnull) stralloc_free(rules) ;
  else rules->len = base ;
  return 0 ;
}

static inline int s6dns_rci_init_rules (s6dns_rci_t_ref rci, char const *file, char *tmp, size_t max, size_t *size)
{
  unsigned int num = 0 ;
  char const *x = getenv("DNSQUALIFY") ;
  if (x)
  {
    if (!stringrules(&rci->rules, x, &num)) return 0 ;
  }
  else
  {
    size_t i = 0 ;
    if (!*size)
    {
      *size = readit(file, tmp, max) ;
      if (!*size) return 0 ;
    }
    while (i < *size)
    {
      size_t j = byte_chr(tmp + i, *size - i, '\n') ;
      if ((i + j < *size) && (j > 8U)
       && (!memcmp("domain", tmp + i, 6) || !memcmp("search", tmp + i, 6))
       && ((tmp[i+6] == ' ') || (tmp[i+6] == '\t') || (tmp[i+6] == '\r')))
      {
        size_t k = 0 ;
        int copying = 0 ;
        int notsearching = (tmp[i] != 's') ;
        if (!stralloc_readyplus(&rci->rules, j)) return 0 ;
        for (; 6 + k < j ; k++)
        {
          char c = tmp[i+7+k] ;
          if ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n'))
          {
            if (copying)
            {
              copying = 0 ;
              if ((tmp[i+6+k] != '.') && !stralloc_catb(&rci->rules, ".", 1)) return 0 ;
              if (!stralloc_0(&rci->rules)) return 0 ;
              num++ ;
              if (notsearching) break ;
            }
          }
          else
          {
            copying = 1 ;
            if (!stralloc_catb(&rci->rules, &c, 1)) return 0 ;
          }
        }
      }
      i += j + 1 ;
    }
  }
  if (!stralloc_0(&rci->rules)) return 0 ; /* empty rule to finish */
  num++ ;
  rci->rulesnum = num ;
  stralloc_shrink(&rci->rules) ;
  return 1 ;
}

int s6dns_rci_init (s6dns_rci_t *rci, char const *file)
{
  char tmp[4096] ;
  size_t size = 0 ;
  if (!s6dns_rci_init_servers(rci, file, tmp, 4096, &size)) return 0 ;
  if (!s6dns_rci_init_rules(rci, file, tmp, 4096, &size)) return 0 ;
  return 1 ;
}
