// rootwalk resolves a name by walking from the root servers down, the way a
// recursive resolver does, and can serve those lookups to other programs.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
	"github.com/Rakshit-gen/rootwalk/resolver"
)

const usage = `usage:
  rootwalk [-trace] [-timeout 10s] name [type]   look a name up (type A unless given)
  rootwalk serve [-trace] [-addr 127.0.0.1:5353]  answer other programs' queries, with a cache
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	serving := len(args) > 0 && args[0] == "serve"
	if serving {
		args = args[1:]
	}
	fs := flag.NewFlagSet("rootwalk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	trace := fs.Bool("trace", false, "print each server asked and what it said")
	timeout := fs.Duration("timeout", 10*time.Second, "give up on a lookup after this long")
	addr := fs.String("addr", "127.0.0.1:5353", "where serve listens, UDP and TCP")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if serving {
		if fs.NArg() != 0 {
			fs.Usage()
			return 2
		}
		r := &resolver.Resolver{Net: resolver.Net{}, Timeout: *timeout, Cache: resolver.NewCache()}
		if *trace {
			r.Trace = func(s string) { fmt.Fprintln(stderr, s) }
		}
		return serve(r, *addr, stderr)
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
	// A cache even for one lookup, so a CNAME into a zone already walked starts there.
	r := &resolver.Resolver{Net: resolver.Net{}, Timeout: *timeout, Cache: resolver.NewCache()}
	if *trace {
		r.Trace = func(s string) { fmt.Fprintln(stderr, ";", s) }
	}
	return query(r, fs.Arg(0), t, stdout, stderr)
}

func serve(r *resolver.Resolver, addr string, stderr io.Writer) int {
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
	go func() { errs <- r.ServeTCP(ctx, ln) }()
	go func() { errs <- r.ServeUDP(ctx, pc) }()
	if err := <-errs; err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	hits, misses := r.Cache.Stats()
	fmt.Fprintf(stderr, "stopped; cache answered %d of %d lookups\n", hits, hits+misses)
	return 0
}

func query(r *resolver.Resolver, name string, t dnsmsg.Type, stdout, stderr io.Writer) int {
	start := time.Now()
	ans, err := r.Resolve(context.Background(), name, t)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
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
