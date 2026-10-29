// rootwalk resolves a name by walking from the root servers down, the way a
// recursive resolver does, and can serve those lookups to other programs.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
	"github.com/Rakshit-gen/rootwalk/resolver"
)

const usage = `usage:
  rootwalk [-trace] [-timeout 10s] name [type]   look a name up (type A unless given)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rootwalk", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	trace := fs.Bool("trace", false, "print each server asked and what it said")
	timeout := fs.Duration("timeout", 10*time.Second, "give up on a lookup after this long")
	if err := fs.Parse(args); err != nil {
		return 2
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
	r := &resolver.Resolver{Net: resolver.Net{}, Timeout: *timeout}
	if *trace {
		r.Trace = func(s string) { fmt.Fprintln(stderr, ";", s) }
	}
	return query(r, fs.Arg(0), t, stdout, stderr)
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
