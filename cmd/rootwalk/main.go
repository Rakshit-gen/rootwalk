// rootwalk resolves a name by walking from the root servers down, the way a
// recursive resolver does, and can serve those lookups to other programs.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
	"github.com/Rakshit-gen/rootwalk/resolver"
)

const usage = `usage:
  rootwalk [-trace] [-short] [-6] [-no-minimise] [-timeout 10s] name [type]
                                                    look a name up (type A unless given)
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
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	trace := fs.Bool("trace", false, "print each server asked and what it said")
	short := fs.Bool("short", false, "print only the data of the final records, like dig +short")
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
	if fs.NArg() == 2 {
		var err error
		if t, err = dnsmsg.ParseType(fs.Arg(1)); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	return query(r, fs.Arg(0), t, *short, stdout, stderr)
}

func serve(s *resolver.Server, addr string, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	hits, misses := s.Resolver.Cache.Stats()
	fmt.Fprintf(stderr, "stopped; cache answered %d of %d lookups\n", hits, hits+misses)
	return 0
}

func query(r *resolver.Resolver, name string, t dnsmsg.Type, short bool, stdout, stderr io.Writer) int {
	start := time.Now()
	ans, err := r.Resolve(context.Background(), name, t)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if short {
		for _, rr := range ans.Answers {
			if rr.Type == t {
				fmt.Fprintln(stdout, strings.SplitN(rr.String(), "\t", 4)[3])
			}
		}
		return 0
	}
	for _, rr := range ans.Answers {
		fmt.Fprintln(stdout, rr)
	}
	switch {
	case ans.Rcode == dnsmsg.RcodeNXDomain:
		fmt.Fprintf(stdout, "; %s doesn't exist\n", dnsmsg.Fqdn(name))
	case len(ans.Answers) == 0:
		fmt.Fprintf(stdout, "; %s has no %s records\n", dnsmsg.Fqdn(name), t)
	}
	fmt.Fprintf(stderr, "; %v\n", time.Since(start).Round(time.Millisecond))
	return 0
}
