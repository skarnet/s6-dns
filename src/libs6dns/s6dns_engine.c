/* ISC license. */

#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/uint16.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/error.h>
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
#include <skalibs/socket.h>
#include <skalibs/djbunix.h>
#include <skalibs/ip46.h>
#include <skalibs/random.h>

#include <s6-dns/s6dns-constants.h>
#include <s6-dns/s6dns-message.h>
#include <s6-dns/s6dns-engine.h>


 /* Utility functions */

static inline int qdomain_diff (char const *s1, size_t n1, char const *s2, size_t n2)
{
  return (n1 < n2) ? -1 : (n1 > n2) ? 1 : strncasecmp(s1, s2, n1) ;
}

static int relevant (char const *q, unsigned int qlen, char const *ans, unsigned int anslen, int strict)
{
  {
    s6dns_message_header_t h ;
    uint16_t id ;
    s6dns_message_header_unpack(ans, &h) ;
    if (!h.qr || h.opcode || h.z || (h.counts.qd != 1)) return 0 ;
    if (h.rd != (q[2] & 1)) return 0 ;
    if (strict && !h.aa && !(q[2] & 1)) return 0 ;
    uint16_unpack_big(q, &id) ;
    if (id != h.id) return 0 ;
  }
  {
    char buf[255] ;
    unsigned int pos = 12 ;
    size_t n = s6dns_message_get_domain_nodecode(buf, 255, ans, anslen, &pos) ;
    if (!n) return -1 ;
    if (pos + 4 > anslen) return (errno = EPROTO, -1) ;
    if (qdomain_diff(buf, n, q + 12, qlen - 16)) return 0 ;
    if (memcmp(q + qlen - 4, ans + pos, 4)) return 0 ;
  }
  return 1 ;
}

static int s6dns_mininetstring_read (int fd, stralloc *sa, uint32_t *w)
{
  if (!*w)
  {
    char pack[2] ;
    switch (fd_read(fd, pack, 2))
    {
      case -1 : return -1 ;
      case 0 : return 0 ;
      case 1 : *w = ((uint32_t)pack[0] << 8) | (1U << 31) ; break ;
      case 2 : *w = ((uint32_t)pack[0] << 8) | (uint32_t)pack[1] | (1U << 30) ; break ;
      default : return (errno = EDOM, -1) ;
    }
  }
  if (*w & (1U << 31))
  {
    unsigned char c ;
    switch (fd_read(fd, (char *)&c, 1))
    {
      case -1 : return -1 ;
      case 0 : return (errno = EPIPE, -1) ;
      case 1 : *w |= (uint32_t)c | (1U << 30) ; *w &= ~(1U << 31) ; break ;
      default : return (errno = EDOM, -1) ;
    }
  }
  if (*w & (1U << 30))
  {
    if (!stralloc_readyplus(sa, *w & ~(1U << 30))) return -1 ;
    *w &= ~(1U << 30) ;
  }
  {
    size_t r = allread(fd, sa->s + sa->len, *w) ;
    sa->len += r ; *w -= r ;
  }
  return *w ? -1 : 1 ;
}


 /* Network core functions: transport-dependent */

#ifdef SKALIBS_IPV6_ENABLED
# define socketbind46(fd, ip, port, flag) ((flag) ? socket_bind6(fd, ip, port) : socket_bind4(fd, ip, port))
# define socketudp46(flag) ((flag) ? socket_udp6() : socket_udp4())
# define sockettcp46(flag) ((flag) ? socket_tcp6() : socket_tcp4())
# define socketconnect46(fd, ip, port, flag) ((flag) ? socket_connect6(fd, ip, port) : socket_connect4(fd, ip, port))
# define S6DNS_ENGINE_LOCAL0 IP6_ANY
#else
# define socketbind46(fd, ip, port, flag) ((void)(flag), socket_bind4(fd, ip, port))
# define socketudp46(flag) socket_udp4()
# define sockettcp46(flag) socket_tcp4()
# define socketconnect46(fd, ip, port, flag) socket_connect4(fd, ip, port)
# define S6DNS_ENGINE_LOCAL0 "\0\0\0"
#endif
 
static int randombind (int fd, int flag)
{
  unsigned int i = 0 ;
  for (; i < 10 ; i++)
    if (socketbind46(fd, S6DNS_ENGINE_LOCAL0, 1025 + random_uint32(64510), flag) >= 0) return 1 ;
  return (socketbind46(fd, S6DNS_ENGINE_LOCAL0, 0, flag) >= 0) ;
}

static int thisudp (s6dns_engine_t *dt, tain_t const *stamp)
{
  for (;; dt->curserver++)
  {
    if (dt->curserver >= S6DNS_MAX_SERVERS)
    {
      dt->curserver = 0 ;
      if (++dt->protostate >= 4) return -2 ;
    }
    if (memcmp(s6dns_ip46list_ip(&dt->servers, dt->curserver), S6DNS_ENGINE_LOCAL0, SKALIBS_IP_SIZE)) break ;
  }
  random_string(dt->sa.s + 2, 2) ; /* random query id */
  dt->fd = socketudp46(s6dns_ip46list_is6(&dt->servers, dt->curserver)) ;
  if (dt->fd < 0) return -1 ;
  if (!randombind(dt->fd, s6dns_ip46list_is6(&dt->servers, dt->curserver)))
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    return -1 ;
  }
  if ((socketconnect46(dt->fd, s6dns_ip46list_ip(&dt->servers, dt->curserver), 53, s6dns_ip46list_is6(&dt->servers, dt->curserver)) < 0)
   && (errno != EINPROGRESS))
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    return 0 ;
  }
  tain_add(&dt->localdeadline, stamp, &tain_infinite_relative) ;
  dt->flagreading = 0 ;
  dt->flagwriting = 1 ;
  if (dt->debughook && dt->debughook->pre_send)
    (*dt->debughook->pre_send)(dt, dt->debughook->external) ;
  return 1 ;
}

static int thistcp (s6dns_engine_t *dt, tain_t const *stamp)
{
  for (; dt->curserver < S6DNS_MAX_SERVERS ; dt->curserver++)
    if (memcmp(s6dns_ip46list_ip(&dt->servers, dt->curserver), S6DNS_ENGINE_LOCAL0, SKALIBS_IP_SIZE)) break ;
  if (dt->curserver >= S6DNS_MAX_SERVERS) return -2 ;
  random_string(dt->sa.s + 2, 2) ;
  dt->fd = sockettcp46(s6dns_ip46list_is6(&dt->servers, dt->curserver)) ;
  if (dt->fd < 0) return -1 ;
  if (!randombind(dt->fd, s6dns_ip46list_is6(&dt->servers, dt->curserver)))
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    return -1 ;
  }
  if ((socketconnect46(dt->fd, s6dns_ip46list_ip(&dt->servers, dt->curserver), 53, s6dns_ip46list_is6(&dt->servers, dt->curserver)) < 0)
   && (errno != EINPROGRESS))
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    return 0 ;
  }
  tain_addsec(&dt->localdeadline, stamp, 10) ;
  dt->protostate = 0 ;
  dt->flagtcp = dt->flagconnecting = dt->flagwriting = 1 ;
  dt->flagreading = 0 ;
  if (dt->debughook && dt->debughook->pre_send)
    (*dt->debughook->pre_send)(dt, dt->debughook->external) ;
  return 1 ;
}


 /* all the rest is transport-agnostic */

static int s6dns_engine_prepare (s6dns_engine_t *dt, tain_t const *stamp, int istcp)
{
  for (;; dt->curserver++)
    switch (istcp ? thistcp(dt, stamp) : thisudp(dt, stamp))
    {
      case -2 : return (errno = ENETUNREACH, 0) ;
      case -1 : return 0 ;
      case 0 : break ;
      case 1 : return 1 ;
      default : return (errno = EDOM, 0) ; /* can't happen */
    }
}

static void prepare_next (s6dns_engine_t *dt, tain_t const *stamp, int istcp)
{
  if (!error_isagain(errno))
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    dt->curserver++ ;
    if (s6dns_engine_prepare(dt, stamp, istcp)) errno = EAGAIN ;
  }
}

static int s6dns_engine_write_udp (s6dns_engine_t *dt, tain_t const *stamp)
{
  static unsigned int const s6dns_engine_udp_timeouts[4] = { 1, 3, 11, 45 } ;
  if (fd_send(dt->fd, dt->sa.s + 2, dt->querylen - 2, 0) < (ssize_t)(dt->querylen - 2))
    return (prepare_next(dt, stamp, 0), 0) ;
  tain_addsec(&dt->localdeadline, stamp, s6dns_engine_udp_timeouts[dt->protostate]) ;
  dt->flagwriting = 0 ;
  dt->flagreading = 1 ;
  if (dt->debughook && dt->debughook->post_send)
    (*dt->debughook->post_send)(dt, dt->debughook->external) ;
  return (errno = EAGAIN, 1) ;
}

static int s6dns_engine_write_tcp (s6dns_engine_t *dt, tain_t const *stamp)
{
  size_t r ;
  r = allwrite(dt->fd, dt->sa.s + dt->protostate, dt->querylen - dt->protostate) ;
  dt->protostate += r ;
  if (r) dt->flagconnecting = 0 ;
  if (dt->protostate < dt->sa.len)
  {
    if ((errno == ECONNRESET) && dt->flagconnecting) errno = EAGAIN ;
    prepare_next(dt, stamp, 1) ;
    return 0 ;
  }
  dt->protostate = 0 ;
  tain_addsec(&dt->localdeadline, stamp, 10) ;
  dt->flagwriting = 0 ;
  dt->flagreading = 1 ;
  if (dt->debughook && dt->debughook->post_send)
    (*dt->debughook->post_send)(dt, dt->debughook->external) ;
  return (errno = EAGAIN, 1) ;
}

static int s6dns_engine_read_udp (s6dns_engine_t *dt, tain_t const *stamp)
{
  s6dns_message_header_t h ;
  char buf[513] ;
  ssize_t r = fd_recv(dt->fd, buf, 513, 0) ;
  if (r < 0) return (prepare_next(dt, stamp, 0), 0) ;
  if ((r > 512) || (r < 12)) return (errno = EAGAIN, 0) ;
  switch (relevant(dt->sa.s + 2, dt->querylen - 2, buf, r, dt->flagstrict))
  {
    case -1 : if (!dt->flagstrict) prepare_next(dt, stamp, 0) ; return 0 ;
    case 0 : return (errno = EAGAIN, 0) ;
    case 1 : break ;
    default : return (errno = EDOM, 0) ; /* can't happen */
  }
  if (dt->debughook && dt->debughook->post_recv)
  {
    if (!stralloc_catb(&dt->sa, buf, r)) return 0 ;
    (*dt->debughook->post_recv)(dt, dt->debughook->external) ;
    dt->sa.len = dt->querylen ;
  }
  s6dns_message_header_unpack(buf, &h) ;
  if (h.tc)
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    dt->curserver = 0 ;
    dt->protostate = 0 ;
    if (s6dns_engine_prepare(dt, stamp, 1)) errno = EAGAIN ;
    return 0 ;
  }
  switch (h.rcode)
  {
    case 0 : case 3 : break ; /* normal operation */
    case 1 : case 4 : case 5 :
      memset(s6dns_ip46list_ip(&dt->servers, dt->curserver), 0, SKALIBS_IP_SIZE) ; /* do not query it again */
    default : prepare_next(dt, stamp, 0) ; return 0 ;
  }
  if (!stralloc_catb(&dt->sa, buf, r))
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
    return 0 ;
  }
  fd_close(dt->fd) ; dt->fd = -1 ;
  dt->flagreading = 0 ;
  return 1 ;
}

static int s6dns_engine_read_tcp (s6dns_engine_t *dt, tain_t const *stamp)
{
  ssize_t r = sanitize_read(s6dns_mininetstring_read(dt->fd, &dt->sa, &dt->protostate)) ;
  if (r < 0) return (prepare_next(dt, stamp, 1), 0) ;
  else if (!r) return (errno = EAGAIN, 0) ;
  else if ((dt->sa.len - dt->querylen) < 12)
  {
    errno = EPROTO ;
    goto badanswer ;
  }
  else
  {
    s6dns_message_header_t h ;
    switch (relevant(dt->sa.s + 2, dt->querylen - 2, dt->sa.s + dt->querylen, dt->sa.len - dt->querylen, dt->flagstrict))
    {
      case -1 : if (dt->flagstrict) { dt->sa.len = dt->querylen ; return 0 ; }
      case 0 : goto badanswer ;
      case 1 : break ;
      default : dt->sa.len = dt->querylen ; return (errno = EDOM, 0) ; /* can't happen */
    }
    if (dt->debughook && dt->debughook->post_recv) (*dt->debughook->post_recv)(dt, dt->debughook->external) ;
    s6dns_message_header_unpack(dt->sa.s + dt->querylen, &h) ;
    if (h.tc) goto badanswer ;
    switch (h.rcode)
    {
      case 0 : case 3 : break ; /* normal operation */
      case 1 : case 4 : case 5 :
        memset(s6dns_ip46list_ip(&dt->servers, dt->curserver), 0, SKALIBS_IP_SIZE) ; /* do not query it again */
      default : goto badanswer ;
    }
    fd_close(dt->fd) ; dt->fd = -1 ;
    dt->flagreading = 0 ;
    return 1 ;
  }
 badanswer:
  dt->sa.len = dt->querylen ;
  prepare_next(dt, stamp, 1) ;
  return 0 ;
}


void s6dns_engine_recycle (s6dns_engine_t *dt)
{
  dt->sa.len = 0 ;
  dt->querylen = 0 ;
  memset(&dt->servers, 0, sizeof(s6dns_ip46list_t)) ;
  if (dt->fd >= 0)
  {
    fd_close(dt->fd) ; dt->fd = -1 ;
  }
  dt->status = ECONNABORTED ;
  dt->flagstrict = dt->flagtcp = dt->flagconnecting = dt->flagreading = dt->flagwriting = 0 ;
}

int s6dns_engine_timeout (s6dns_engine_t *dt, tain_t const *stamp)
{
  if (!error_isagain(dt->status)) return (errno = EINVAL, -1) ;
  else if (tain_less(&dt->deadline, stamp)) goto yes ;
  else if (!tain_less(&dt->localdeadline, stamp)) return 0 ;
  else if (dt->flagwriting) goto yes ;
  else if (!dt->flagreading) return 0 ;
  fd_close(dt->fd) ; dt->fd = -1 ;
  dt->curserver++ ;
  if (!s6dns_engine_prepare(dt, stamp, dt->flagtcp))
  {
    s6dns_engine_recycle(dt) ;
    dt->status = errno ;
    return -1 ;
  }
  return 0 ;
 yes:
  s6dns_engine_recycle(dt) ;
  dt->status = ETIMEDOUT ;
  return 1 ;
}

int s6dns_engine_event (s6dns_engine_t *dt, tain_t const *stamp)
{
  if (!error_isagain(dt->status)) return (errno = EINVAL, -1) ;
  if (dt->flagwriting)
    dt->flagtcp ? s6dns_engine_write_tcp(dt, stamp) : s6dns_engine_write_udp(dt, stamp) ;
  else if (dt->flagreading)
  {
    if ((dt->flagtcp) ? s6dns_engine_read_tcp(dt, stamp) : s6dns_engine_read_udp(dt, stamp))
    {
      dt->status = 0 ;
      return 1 ;
    }
  }
  else return (errno = EINVAL, -1) ;
  if (error_isagain(errno)) return 0 ;
  s6dns_engine_recycle(dt) ;
  dt->status = errno ;
  return -1 ;
}

int s6dns_engine_init_r (s6dns_engine_t *dt, s6dns_ip46list_t const *servers, uint32_t options, char const *q, unsigned int qlen, uint16_t qtype, s6dns_debughook_t const *dbh, tain_t const *deadline, tain_t const *stamp)
{
  s6dns_message_header_t h = S6DNS_MESSAGE_HEADER_ZERO ;
  if (!stralloc_ready(&dt->sa, qlen + 18)) return 0 ;
  dt->deadline = *deadline ;
  dt->localdeadline = *stamp ;
  dt->querylen = qlen + 18 ;
  dt->sa.len = dt->querylen ;
  dt->servers = *servers ;
  dt->debughook = dbh ;
  dt->status = EAGAIN ;
  dt->flagconnecting = dt->flagreading = dt->flagwriting = 0 ;
  dt->flagstrict = !!(options & S6DNS_O_STRICT) ;
  h.rd = !!(options & S6DNS_O_RECURSIVE) ;
  h.counts.qd = 1 ;
  uint16_pack_big(dt->sa.s, qlen + 16) ;
  s6dns_message_header_pack(dt->sa.s + 2, &h) ;
  memcpy(dt->sa.s + 14, q, qlen) ;
  uint16_pack_big(dt->sa.s + 14 + qlen, qtype) ;
  uint16_pack_big(dt->sa.s + 16 + qlen, S6DNS_C_IN) ;
  if (qlen > 496) dt->flagtcp = 1 ;
  else
  {
    dt->flagtcp = 0 ;
    dt->protostate = h.rd ;
  }
  if (!s6dns_engine_prepare(dt, stamp, dt->flagtcp))
  {
    s6dns_engine_recycle(dt) ;
    return 0 ;
  }
  return 1 ;
}
