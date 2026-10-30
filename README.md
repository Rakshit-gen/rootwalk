# rootwalk

A recursive DNS resolver in Go with no dependencies outside the standard
library. It starts at the root servers, follows referrals down to the server
that holds the answer, and can serve those lookups to `dig` or anything else
on your machine.

## Install

```
curl -fsSL https://raw.githubusercontent.com/Rakshit-gen/rootwalk/main/scripts/install.sh | sh
```

This puts the release binary for Linux or macOS (amd64 or arm64) in
`~/.local/bin` after checking it against the release's `checksums.txt`. It
needs a tagged release, and none has been tagged yet. Until then, build it
with Go 1.25: `go build -o rootwalk ./cmd/rootwalk`.

## Use

```
rootwalk example.com
rootwalk wikipedia.org MX
rootwalk -short www.wikipedia.org
rootwalk -json go.dev AAAA
rootwalk -x 8.8.8.8
rootwalk -trace www.bbc.co.uk

rootwalk serve -addr 127.0.0.1:5353 -log
dig @127.0.0.1 -p 5353 go.dev
```

`-trace` prints each server asked and what it said, with nested lookups
indented:

```
; 202.12.27.33 sent org. A to org. (6 servers, 6 addresses in glue)
; asking for the full name after rakshit-not-real.org. A: rcode 3, <nil>
; 199.19.56.1 says nope.rakshit-not-real.org. doesn't exist
; nope.rakshit-not-real.org. doesn't exist
; 3 queries, 399ms
```

Other flags: `-6` to reach nameservers over IPv6 too, `-no-minimise` to send
every server the full name, `-timeout` for the whole lookup. `serve` also
takes `-allow` (who may ask), `-rate` (UDP queries a second per client) and
`-log`. `rootwalk -h` lists them all. Send `serve` a SIGHUP to empty its
cache.

## Measured vs Claimed

| Claim | Value | How measured | Date |
|---|---|---|---|
| Cold lookup, median | 230 ms and 170 ms (two runs) | `scripts/bench.sh`: `rootwalk serve`, then `dig` once per name in `scripts/names.txt`, median over all 11 names. Apple M4 on my home network, local | 2026-10-31 |
| Cold lookup, range | 19 ms to 1825 ms | same runs; the NXDOMAIN name is the fastest, www.wikipedia.org and www.bbc.co.uk (CNAME chains) the slowest | 2026-10-31 |
| Cold lookup, median, before the changes below | 271 ms and 202 ms (two runs) | same script, median over the 10 names that exist (the NXDOMAIN row left out) | 2026-10-30 |
| Warm lookup | 0 ms for all 11 names | second `dig` for each name in the same runs; dig reports whole milliseconds | 2026-10-30 and 2026-10-31 |
| Cache hits during the bench | 17 of 54 lookups | what `rootwalk serve` prints on exit; nested lookups for nameserver addresses count too | 2026-10-30 and 2026-10-31 |
| Resolver cost without the network | 8.1 µs cold, 1.1 µs warm | `make bench-go` (`BenchmarkResolveCold`, `BenchmarkResolveWarm`), three in-memory servers, Apple M4 | 2026-10-31 |
| Packing a four-server referral | 1653 ns, 21 allocations | `make bench-go` (`BenchmarkPack`); 2619 ns and 68 allocations before names were compressed in place | 2026-10-31 |
| Message parser fuzzing | 10M inputs in 30 s, no failures | `make fuzz` (`FuzzUnpack`), Apple M4 | 2026-10-30 |

The two cold medians aren't measured the same way: the newer one includes
the NXDOMAIN name, which is fast because example.com's servers are cached by
then. The runs also hit different servers, since rootwalk now picks them by
round-trip time and tries new ones in random order. Latency depends mostly
on your distance to those servers, so expect different numbers on another
network.

## How it works

- `dnsmsg` packs and unpacks DNS messages: name compression both ways
  (pointers must point backwards), the 63 and 255 byte limits, EDNS0, and
  A, AAAA, NS, CNAME, PTR, MX, SOA, TXT, SRV and CAA records. Other types
  are carried as raw bytes. A message with bytes left over is rejected.
- `resolver.Net` sends a query over UDP with a random ID and an EDNS0 buffer
  of 1232 bytes, ignores replies that don't match, and retries over TCP when
  the reply is truncated.
- `resolver.Resolver` walks down from the root:
  - Each server is told only one label more than the zone it serves (QNAME
    minimisation, RFC 9156), so the root sees `com.` and not
    `www.example.com.`. An NXDOMAIN for a shortened name is checked by asking
    for the full one, since some servers get empty names wrong.
  - A referral only counts if it points strictly below the zone the server
    was asked as. Glue, and records for a CNAME's target, are only believed
    from a server whose zone they're in.
  - Nameservers without glue are looked up (at most eight deep, at most four
    per referral), and CNAME chains are followed across zones (at most eight,
    loops refused). One lookup sends at most 64 queries, so a hostile
    referral can't turn it into hundreds.
  - Servers are tried fastest first by smoothed round-trip time, new ones
    before known ones, and each gets four times its usual round trip before
    the next is tried. One that answers SERVFAIL, REFUSED or FORMERR is
    skipped. One deadline, 10 s by default, covers the whole lookup.
  - Identical lookups running at once share one walk.
- `resolver.Cache` keeps up to 100,000 record sets for their TTL (capped at
  24 hours) and drops the least recently used past that. Negative answers
  last for the SOA's minimum (RFC 2308). It remembers the servers for each
  zone a referral named, so the next name under that zone starts there. A
  name asked for in the last tenth of its TTL is refreshed in the background,
  and an expired answer is served for up to a day if every server for it
  stops answering (RFC 8767).
- `resolver.Server` answers on UDP and TCP from one cache. By default only
  loopback and private addresses may ask. A UDP client over its rate gets an
  empty reply with TC set, which a real client follows over TCP. Past 1000
  lookups in flight, new queries get SERVFAIL straight away. A UDP reply
  that doesn't fit the client's buffer goes out with TC set and no records.

## Status

Works: everything above, with 70 tests, a fuzz target and Go benchmarks. The
tests use fake servers in memory, plus a loopback server for the UDP and TCP
paths. CI runs them on Linux and macOS and does one live lookup.

Not done:

- No DNSSEC validation.
- IPv6 is off unless you pass `-6`, since on a network without an IPv6
  route every IPv6 server tried costs a timeout.
- The root server addresses are built in and never refreshed from the root
  itself.
- The rate limit only applies to UDP and is per address, not per network.

## License

MIT
