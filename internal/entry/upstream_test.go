package entry

import "testing"

func TestUpstreamsResolveNamed(t *testing.T) {
	u := Upstreams{
		"a": {Name: "a", ProxyAddr: "resin-a:2260", Token: "ta"},
		"b": {Name: "b", ProxyAddr: "resin-b:2260", Token: "tb"},
	}
	got, ok := u.Resolve("b")
	if !ok || got.ProxyAddr != "resin-b:2260" || got.Token != "tb" {
		t.Fatalf("resolved %+v ok=%v, want instance b", got, ok)
	}
}

// An unknown name must not silently borrow another instance: routing a lease to
// the wrong Resin returns 401 and looks like a broken pool.
func TestUpstreamsResolveUnknownFallsBackToDefault(t *testing.T) {
	u := Upstreams{
		"main": {Name: "main", ProxyAddr: "resin-main:2260"},
		"alt":  {Name: "alt", ProxyAddr: "resin-alt:2260"},
	}
	if got, ok := u.Resolve("gone"); ok {
		t.Fatalf("resolved %+v for an unknown name with no default, want failure", got)
	}
	u[DefaultUpstream] = Upstream{Name: DefaultUpstream, ProxyAddr: "resin-default:2260"}
	got, ok := u.Resolve("gone")
	if !ok || got.Name != DefaultUpstream {
		t.Fatalf("resolved %+v ok=%v, want the default instance", got, ok)
	}
}

func TestUpstreamsResolveSingleInstance(t *testing.T) {
	u := Upstreams{"x": {Name: "x", ProxyAddr: "resin-x:2260"}}
	got, ok := u.Resolve("")
	if !ok || got.Name != "x" {
		t.Fatalf("resolved %+v ok=%v, want the only instance", got, ok)
	}
	if _, ok := (Upstreams{}).Resolve("x"); ok {
		t.Fatal("empty registry must not resolve")
	}
}

func TestUpstreamsNamesSorted(t *testing.T) {
	u := Upstreams{"b": {}, "a": {}, "c": {}}
	got := u.Names()
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("names = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}
}
