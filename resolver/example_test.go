package resolver_test

import (
	"context"
	"fmt"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
	"github.com/Rakshit-gen/rootwalk/resolver"
)

// Looking a name up from the root, with a cache so repeat lookups are free.
// This needs the network, so it isn't run as a test.
func ExampleResolver_Resolve() {
	r := &resolver.Resolver{Net: resolver.Net{}, Cache: resolver.NewCache()}
	ans, err := r.Resolve(context.Background(), "www.wikipedia.org", dnsmsg.TypeA)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, rr := range ans.Answers {
		fmt.Println(rr) // the CNAME to dyna.wikimedia.org., then its A record
	}
	fmt.Println(ans.Queries, "queries")
}

// Serving lookups to other programs on port 5353.
func ExampleServer() {
	s := &resolver.Server{
		Resolver: &resolver.Resolver{Net: resolver.Net{}, Cache: resolver.NewCache()},
		Rate:     100,
	}
	_ = s // then s.ServeUDP and s.ServeTCP on a listener, as cmd/rootwalk does
}
