# Changelog

## Unreleased

Resolving

- Each server is only told one label more than its zone (QNAME
  minimisation, RFC 9156). `-no-minimise` turns it off.
- Servers are picked by smoothed round-trip time, untried ones first, and
  given up on after four times their usual round trip.
- Records for a CNAME target are only taken from a server whose zone they're in.
- A lookup sends at most 64 queries and looks up at most four glueless
  nameservers per referral.
- A name that can't be written in a message is rejected before any query.
- IPv6: the root servers' IPv6 addresses, IPv6 glue and AAAA lookups for
  glueless nameservers, behind `-6`.
- Identical lookups in flight at once share one walk.
- Each answer counts the queries behind it.

Caching

- At most 100,000 record sets, least recently used dropped first, and
  cached zones capped at a tenth of that.
- Expired answers are served for up to a day when every server stops
  answering (RFC 8767).
- Names asked for in the last tenth of their TTL are refreshed in the background.
- The one-shot command caches too, so a CNAME chain reuses zones it already walked.

Serving

- Only loopback and private clients by default; `-allow` for others.
- `-rate` per-client UDP limit, 100 a second by default; over it, an empty
  truncated reply.
- SERVFAIL straight away past 1000 lookups in flight.
- EDNS echoed on every reply, BADVERS for unknown EDNS versions.
- `-log` for a line per query, and SIGHUP to empty the cache.

Messages

- Names are compressed when packing, inside NS, CNAME, PTR, MX and SOA
  data too.
- SRV and CAA records.

Command

- `-short`, `-json`, `-x` for reverse lookups, `-version`, and a usage
  message that lists every flag.
- Trace lines are indented for nested lookups.

Building and releasing

- goreleaser builds for Linux and macOS on amd64 and arm64 when a `v` tag
  is pushed, and `scripts/install.sh` installs one after checking its checksum.
- CI on macOS as well as Linux.
- Go benchmarks (`make bench-go`), and the bench script prints the median.

## First version

A stdlib-only recursive resolver: message parsing with a fuzz target, UDP
with TCP fallback, referrals with bailiwick checks, glueless nameservers,
CNAME chains, negative answers, a TTL cache, and `rootwalk serve` on UDP
and TCP.
