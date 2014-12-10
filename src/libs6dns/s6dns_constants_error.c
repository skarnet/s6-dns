/* ISC license. */

#include <errno.h>
#include <skalibs/error.h>
#include <s6-dns/s6dns-constants.h>

static s6dns_constants_error_message_t const array[] =
{
  { ENETUNREACH, "no available DNS server" },
  { EBADMSG, "server did not understand query" },
  { EBUSY, "server failure" },
  { ENOENT, "no such domain" },
  { ENOTSUP, "not implemented in server" },
  { ECONNREFUSED, "server refused" },
  { EIO, "unknown network error" },
  { EAGAIN, "query still processing" },
  { ETIMEDOUT, "query timed out" },
  { EPROTO, "malformed packet" },
  { EDOM, "internal error (please submit a bug-report)" },
  { -1, "unknown error" }
} ;

s6dns_constants_error_message_t const *const s6dns_constants_error = array ;
