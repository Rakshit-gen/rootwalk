// rootwalk resolves a name by walking from the root servers down, the way a
// recursive resolver does, and can serve those lookups to other programs.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
	"github.com/Rakshit-gen/rootwalk/resolver"
)

// version is set by the release build.
var version = "dev"

const usage = `usage:
  rootwalk [-trace] [-short|-json] [-6] [-no-minimise] [-timeout 10s] name [type]
                                                    look a name up (type A unless given)
  rootwalk -x [flags] address                       look up the name for an IP address
  rootwalk -version
  rootwalk serve [-trace] [-6] [-no-minimise] [-addr 127.0.0.1:5353] [-allow 10.1.0.0/16,...] [-rate 100] [-log]
                                                    answer other programs' queries, with a cache
`

func main() {
	os.Exit(run(os.Args[1:], resolver.Net{}, os.Stdout, os.Stderr))
}

// run is the whole command, with the network passed in so tests can fake it.
func run(args []string, network resolver.Exchanger, stdout, stderr io.Writer) int {
	serving := len(args) > 0 && args[0] == "serve"
	if serving {
		args = args[1:]
	}
	fs := flag.NewFlagSet("rootwalk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage, "\nflags:\n")
		fs.PrintDefaults()
	}
	trace := fs.Bool("trace", false, "print each server asked and what it said")
	short := fs.Bool("short", false, "print only the data of the final records, like dig +short")
	showVersion := fs.Bool("version", false, "print the version and exit")
	reverse := fs.Bool("x", false, "the argument is an IP address: look up its PTR record")
	asJSON := fs.Bool("json", false, "print the answer as JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "give up on a lookup after this long")
	v6 := fs.Bool("6", false, "reach nameservers over IPv6 too")
	full := fs.Bool("no-minimise", false, "send every server the full name (RFC 9156 minimisation is on by default)")
	allow := fs.String("allow", "", "for serve: comma-separated prefixes that may ask (default loopback and private)")
	logQueries := fs.Bool("log", false, "for serve: print a line per query")
	rate := fs.Float64("rate", 100, "for serve: UDP queries a second per client, 0 for no limit")
	addr := fs.String("addr", "127.0.0.1:5353", "where serve listens, UDP and TCP")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "rootwalk", version)
		return 0
	}
	// A cache even for one lookup, so a CNAME into a zone already walked starts there.
	r := &resolver.Resolver{Net: network, Timeout: *timeout, Cache: resolver.NewCache(), IPv6: *v6, NoMinimise: *full}
	if *trace {
		r.Trace = func(s string) { fmt.Fprintln(stderr, ";", s) }
	}
	if serving {
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		s := &resolver.Server{Resolver: r, Rate: *rate}
		if *logQueries {
			s.Log = func(l string) { fmt.Fprintln(stderr, time.Now().Format(time.TimeOnly), l) }
		}
		for _, p := range strings.FieldsFunc(*allow, func(c rune) bool { return c == ',' }) {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(p))
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			s.Allow = append(s.Allow, prefix)
		}
		return serve(s, *addr, stderr)
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return 2
	}
	t := dnsmsg.TypeA
	name := fs.Arg(0)
	if *reverse {
		addr, err := netip.ParseAddr(name)
		if err != nil || fs.NArg() != 1 {
			fmt.Fprintln(stderr, "-x takes one IP address")
			return 2
		}
		name, t = reverseName(addr), dnsmsg.TypePTR
	} else if fs.NArg() == 2 {
		var err error
		if t, err = dnsmsg.ParseType(fs.Arg(1)); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	out := text
	switch {
	case *short && *asJSON:
		fmt.Fprintln(stderr, "-short and -json don't go together")
		return 2
	case *short:
		out = shortText
	case *asJSON:
		out = jsonOut
	}
	return query(r, name, t, out, stdout, stderr)
}

func serve(s *resolver.Server, addr string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			s.Resolver.Cache.Flush()
			fmt.Fprintln(stderr, "cache flushed")
		}
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stderr, "serving on %s, UDP and TCP\n", addr)
	errs := make(chan error, 2)
	go func() { errs <- s.ServeTCP(ctx, ln) }()
	go func() { errs <- s.ServeUDP(ctx, pc) }()
	if err := <-errs; err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	st := s.Resolver.Cache.Stats()
	fmt.Fprintf(stderr, "stopped; cache answered %d of %d lookups (%d stale) and held %d record sets\n",
		st.Hits, st.Hits+st.Misses, st.Stale, st.Entries)
	return 0
}

// reverseName is the in-addr.arpa or ip6.arpa name for an address.
func reverseName(a netip.Addr) string {
	a = a.Unmap()
	var parts []string
	b := a.AsSlice()
	if a.Is4() {
		for i := len(b) - 1; i >= 0; i-- {
			parts = append(parts, strconv.Itoa(int(b[i])))
		}
		return strings.Join(parts, ".") + ".in-addr.arpa."
	}
	for i := len(b) - 1; i >= 0; i-- {
		parts = append(parts, strconv.FormatUint(uint64(b[i]&0xf), 16), strconv.FormatUint(uint64(b[i]>>4), 16))
	}
	return strings.Join(parts, ".") + ".ip6.arpa."
}

// An output writes the answer to name's type t lookup.
type output func(w io.Writer, name string, t dnsmsg.Type, ans resolver.Answer, took time.Duration)

func query(r *resolver.Resolver, name string, t dnsmsg.Type, out output, stdout, stderr io.Writer) int {
	start := time.Now()
	ans, err := r.Resolve(context.Background(), name, t)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	took := time.Since(start)
	out(stdout, dnsmsg.Fqdn(name), t, ans, took)
	fmt.Fprintf(stderr, "; %d queries, %v\n", ans.Queries, took.Round(time.Millisecond))
	return 0
}

func text(w io.Writer, name string, t dnsmsg.Type, ans resolver.Answer, _ time.Duration) {
	for _, rr := range ans.Answers {
		fmt.Fprintln(w, rr)
	}
	switch {
	case ans.Rcode == dnsmsg.RcodeNXDomain:
		fmt.Fprintf(w, "; %s doesn't exist\n", name)
	case len(ans.Answers) == 0:
		fmt.Fprintf(w, "; %s has no %s records\n", name, t)
	}
}

func shortText(w io.Writer, _ string, t dnsmsg.Type, ans resolver.Answer, _ time.Duration) {
	for _, rr := range ans.Answers {
		if rr.Type == t {
			fmt.Fprintln(w, data(rr))
		}
	}
}

// data is a record's data as text, the part after name, TTL and type.
func data(rr dnsmsg.RR) string { return strings.SplitN(rr.String(), "\t", 4)[3] }

type jsonRR struct {
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	Type string `json:"type"`
	Data string `json:"data"`
}

func jsonOut(w io.Writer, name string, t dnsmsg.Type, ans resolver.Answer, took time.Duration) {
	conv := func(rrs []dnsmsg.RR) []jsonRR {
		out := []jsonRR{}
		for _, rr := range rrs {
			out = append(out, jsonRR{rr.Name, rr.TTL, rr.Type.String(), data(rr)})
		}
		return out
	}
	rcode := map[uint8]string{dnsmsg.RcodeSuccess: "NOERROR", dnsmsg.RcodeNXDomain: "NXDOMAIN"}[ans.Rcode]
	json.NewEncoder(w).Encode(struct {
		Name      string   `json:"name"`
		Type      string   `json:"type"`
		Rcode     string   `json:"rcode"`
		Answers   []jsonRR `json:"answers"`
		Authority []jsonRR `json:"authority"`
		MS        int64    `json:"ms"`
	}{name, t.String(), rcode, conv(ans.Answers), conv(ans.Authority), took.Milliseconds()})
}
