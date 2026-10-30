package resolver

import (
	"testing"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

// The resolver's own cost, with servers that answer instantly from memory.

func BenchmarkResolveCold(b *testing.B) {

	_, r := world(b)
	for b.Loop() {
		r.Cache = NewCache()
		if _, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResolveWarm(b *testing.B) {

	_, r := world(b)
	r.Cache = NewCache()
	r.Resolve(ctx, "www.example.test", dnsmsg.TypeA)
	for b.Loop() {
		if _, err := r.Resolve(ctx, "www.example.test", dnsmsg.TypeA); err != nil {
			b.Fatal(err)
		}
	}
}
