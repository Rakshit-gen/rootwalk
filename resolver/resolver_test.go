package resolver

import (
	"context"
	"testing"

	"github.com/Rakshit-gen/rootwalk/dnsmsg"
)

var ctx = context.Background()

func TestWalksDownFromTheRoot(t *testing.T) {
	n, r := world(t)
	var steps []string
	r.Trace = func(s string) { steps = append(steps, s) }
	ans, err := r.Resolve(ctx, "WWW.example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Answers) != 1 || ans.Answers[0].Addr.String() != "192.0.2.80" {
		t.Fatalf("got %v", ans.Answers)
	}
	if n.queries != 3 || len(steps) != 3 {
		t.Fatalf("%d queries, steps %q", n.queries, steps)
	}
}

func TestTriesTheNextServerWhenOneIsDown(t *testing.T) {
	n, r := world(t)
	r.Roots = addrs("10.9.9.9", "10.0.0.1") // the first doesn't exist
	if _, err := r.Resolve(ctx, "example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if n.queries != 4 {
		t.Fatalf("%d queries, want 4", n.queries)
	}
}
