BIN_TARGETS := \
skadnsd \
s6-randomip \
s6-dnsqualify \
s6-dnsip4 \
s6-dnsip6 \
s6-dnsmx \
s6-dnsname \
s6-dnsns \
s6-dnssoa \
s6-dnssrv \
s6-dnstxt \
s6-dnsip4-filter \
s6-dnsip6-filter \
s6-dnsname-filter \
s6-dnsq \
s6-dnsqr

LIBEXEC_TARGETS :=

ifdef DO_SHARED
SHARED_LIBS := libs6dns.so libskadns.so
endif

ifdef DO_STATIC
STATIC_LIBS := libs6dns.a libskadns.a
endif
