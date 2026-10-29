# rootwalk

A recursive DNS resolver in Go with no dependencies outside the standard
library. It starts at the root servers, follows referrals down to the server
that holds the answer, and can serve those lookups to `dig` or anything else
on your machine.

## Quickstart

```
go build -o rootwalk ./cmd/rootwalk

./rootwalk example.com
./rootwalk -trace www.wikipedia.org
./rootwalk wikipedia.org MX

./rootwalk serve -addr 127.0.0.1:5353
dig @127.0.0.1 -p 5353 go.dev
```

`-trace` prints each server asked and what it said:

```
; 198.41.0.4 sent nope.rakshit-not-real.org. A to org. (6 servers, 6 with addresses)
; 199.249.112.1 says nope.rakshit-not-real.org. doesn't exist
; nope.rakshit-not-real.org. doesn't exist
```

## Measured vs Claimed

| Claim | Value | How measured | Date |
|---|---|---|---|
| Cold lookup, median of 10 names | 271 ms and 202 ms (two runs) | `scripts/bench.sh`: `rootwalk serve`, then `dig` once per name in `scripts/names.txt`. Apple M4 on my home network, local | 2026-10-30 |
| Cold lookup, range | 137 ms to 1091 ms | same runs; www.wikipedia.org is the slowest (a CNAME into another zone) | 2026-10-30 |
| Warm lookup | 0 ms for all 11 names | same runs, second `dig` for each name. dig reports whole milliseconds | 2026-10-30 |
| Cache hits during the bench | 17 of 54 lookups | what `rootwalk serve` prints on exit; nested lookups for nameserver addresses count too | 2026-10-30 |
| Message parser fuzzing | 10M inputs in 30 s, no failures | `make fuzz` (`FuzzUnpack`), Apple M4 | 2026-10-30 |

The NXDOMAIN row in the bench (does-not-exist.example.com, 21 and 22 ms
cold) is fast because example.com's servers were already cached from the
first name. Latency depends mostly on your distance to the servers asked,
so expect different numbers on another network.

## How it works

- `dnsmsg` packs and unpacks DNS messages: name compression (pointers must
  point backwards), the 63 and 255 byte limits, and A, AAAA, NS, CNAME, PTR,
  MX, SOA and TXT records. Other types are carried as raw bytes. A message
  with bytes left over is rejected.
- `resolver.Net` sends a query over UDP with a random ID and an EDNS0 buffer
  of 1232 bytes, ignores replies that don't match, and retries over TCP when
  the reply is truncated.
- `resolver.Resolver` walks down from the root. A referral only counts if it
  points strictly below the zone the server was asked as, and glue is only
  believed for names inside that zone. Nameservers without glue are looked up
  (at most eight deep), CNAME chains are followed across zones (at most
  eight, loops refused), and a server that times out or answers SERVFAIL,
  REFUSED or FORMERR is skipped for the next one. One deadline, 10 s by
  default, covers the whole lookup.
- `resolver.Cache` keeps answers for their TTL (capped at 24 hours), negative
  answers for the SOA's minimum as RFC 2308 says, and the servers for each
  zone a referral named, so the next name under that zone starts there.
- `rootwalk serve` answers on UDP and TCP from one cache. A UDP reply that
  doesn't fit the client's buffer goes out with TC set and no records.

## Status

Works: everything above, with 38 tests and a fuzz target. The tests use fake
servers in memory, plus a loopback server for the UDP and TCP paths. CI also
does one live lookup.

Not done:

- IPv4 only. AAAA records are answered, but nameservers are only reached
  over IPv4.
- No DNSSEC validation and no QNAME minimisation, so every server on the way
  sees the full name.
- The cache has no size limit. Expired entries are only dropped when looked
  up.
- No rate limiting. `serve` listens on 127.0.0.1 by default; don't point it
  at a public address, or it becomes an open resolver.

## License

MIT
