/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/bytestr.h>
#include <skalibs/bitarray.h>
#include <skalibs/fmtscan.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/stralloc.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-rci.h>

static unsigned int readit (char const *file, char *buf, unsigned int max)
{
  register int r = openreadnclose(file, buf, max - 1) ;
  if (r < 0)
  {
    if (errno != ENOENT) return 0 ;
    else r = 0 ;
  }
  buf[r++] = '\n' ;
  return (unsigned int)r ;
}

static inline int s6dns_rci_init_servers (s6dns_rci_t *rci, char const *file, char *tmp, unsigned int max, unsigned int *size)
{
  ip46_t tmplist[S6DNS_MAX_SERVERS] ;
  unsigned int num = 0 ;
  char const *x = env_get("DNSCACHEIP") ;
  if (x) ip46_scanlist(tmplist, S6DNS_MAX_SERVERS, x, &num) ;
  if (!num)
  {
    unsigned int i = 0 ;
    *size = readit(file, tmp, max) ;
    if (!*size) return 0 ;
    while ((i < *size) && (num < S6DNS_MAX_SERVERS))
    {
      register unsigned int j = byte_chr(tmp + i, *size - i, '\n') ;
      if ((i + j < *size) && (j > 13U) && !byte_diff("nameserver", 10, tmp + i))
      {
        register unsigned int k = 0 ;
        while ((tmp[i+10+k] == ' ') || (tmp[i+10+k] == '\t')) k++ ;
        if (k && ip46_scan(tmp+i+10+k, tmplist + num)) num++ ;
      }
      i += j + 1 ;
    }
  }
  if (!num)
  {
    num = 1 ;
    byte_copy(tmplist[0].ip, SKALIBS_IP_SIZE, S6DNS_LOCALHOST_IP) ;
#ifdef SKALIBS_IPV6_ENABLED
    tmplist[0].is6 = 1 ;
#endif
  }

  {
    register unsigned int i = 0 ;
    byte_zero(&rci->servers, sizeof(s6dns_ip46list_t)) ;
    for (; i < num ; i++)
    {
      byte_copy(rci->servers.ip + SKALIBS_IP_SIZE * i, SKALIBS_IP_SIZE, tmplist[i].ip) ;
#ifdef SKALIBS_IPV6_ENABLED
      if (ip46_is6(tmplist+i)) bitarray_set(rci->servers.is6, i) ;
#endif
    }
  }
  return 1 ;
}

static inline int stringrules (stralloc *rules, char const *s, unsigned int *num)
{
  unsigned int n = 0 ;
  int crunching = 1 ;
  int wasnull = !rules->s ;
  unsigned int base = rules->len ;
  char c = ' ' ;
  while (c)
  {
    c = *s++ ;
    if (byte_chr(" \t\n\r", 5, c) < 5)
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

static inline int s6dns_rci_init_rules (s6dns_rci_t_ref rci, char const *file, char *tmp, unsigned int max, unsigned int *size)
{
  unsigned int num = 0 ;
  char const *x = env_get("DNSQUALIFY") ;
  if (x)
  {
    if (!stringrules(&rci->rules, x, &num)) return 0 ;
  }
  else
  {
    unsigned int i = 0 ;
    if (!*size)
    {
      *size = readit(file, tmp, max) ;
      if (!*size) return 0 ;
    }
    while (i < *size)
    {
      register unsigned int j = byte_chr(tmp + i, *size - i, '\n') ;
      if ((i + j < *size) && (j > 8U)
       && (!byte_diff("domain", 6, tmp + i) || !byte_diff("search", 6, tmp + i))
       && ((tmp[i+6] == ' ') || (tmp[i+6] == '\t') || (tmp[i+6] == '\r')))
      {
        unsigned int k = 0 ;
        int copying = 0 ;
        register int notsearching = (tmp[i] != 's') ;
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
  unsigned int size = 0 ;
  if (!s6dns_rci_init_servers(rci, file, tmp, 4096, &size)) return 0 ;
  if (!s6dns_rci_init_rules(rci, file, tmp, 4096, &size)) return 0 ;
  return 1 ;
}
