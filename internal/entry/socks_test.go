package entry

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// fakeResinSOCKS5 stands in for Resin's forward proxy: it records which account
// the username named and forwards the CONNECT to the real target.
type fakeResinSOCKS5 struct {
	ln net.Listener

	mu       sync.Mutex
	lastUser string
	calls    int
}

func newFakeResin(t *testing.T) *fakeResinSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeResinSOCKS5{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeResinSOCKS5) username() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastUser
}

func (f *fakeResinSOCKS5) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	// Greeting.
	h := make([]byte, 2)
	if _, err := io.ReadFull(br, h); err != nil {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	c.Write([]byte{0x05, 0x02})

	// Username/password auth.
	ah := make([]byte, 2)
	if _, err := io.ReadFull(br, ah); err != nil {
		return
	}
	user := make([]byte, int(ah[1]))
	if _, err := io.ReadFull(br, user); err != nil {
		return
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(br, pl); err != nil {
		return
	}
	pass := make([]byte, int(pl[0]))
	if _, err := io.ReadFull(br, pass); err != nil {
		return
	}
	f.mu.Lock()
	f.lastUser = string(user)
	f.calls++
	f.mu.Unlock()
	if string(pass) != "tok" {
		c.Write([]byte{0x01, 0x01})
		return
	}
	c.Write([]byte{0x01, 0x00})

	// CONNECT request.
	rh := make([]byte, 4)
	if _, err := io.ReadFull(br, rh); err != nil {
		return
	}
	var host string
	switch rh[3] {
	case 0x01:
		b := make([]byte, 4)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(br, l)
		b := make([]byte, int(l[0]))
		io.ReadFull(br, b)
		host = string(b)
	}
	pb := make([]byte, 2)
	io.ReadFull(br, pb)
	port := binary.BigEndian.Uint16(pb)

	up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 2*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go func() { io.Copy(up, br) }()
	io.Copy(c, up)
}

// echoServer returns "pong" for whatever it receives.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startForward(t *testing.T, p *pool.Pool, upstream string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	f := &Forward{
		Pool:        p,
		Log:         quietLogger(),
		Upstream:    upstream,
		Token:       "tok",
		Platform:    "opencode",
		DialTimeout: 3 * time.Second,
	}
	go f.Serve(ln)
	return ln.Addr().String()
}

// The account must reach the upstream, otherwise every caller would share one
// egress and the pool would be pointless.
func TestForwardSOCKS5CarriesAccount(t *testing.T) {
	resin := newFakeResin(t)
	target := echoServer(t)
	proxyAddr := startForward(t, seeded(), resin.ln.Addr().String())

	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting offering only username/password.
	c.Write([]byte{0x05, 0x01, 0x02})
	sel := make([]byte, 2)
	if _, err := io.ReadFull(c, sel); err != nil {
		t.Fatal(err)
	}
	if sel[1] != 0x02 {
		t.Fatalf("proxy selected method %d, want 2", sel[1])
	}

	user := "opencode.leaseA"
	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, 3, 't', 'o', 'k')
	c.Write(auth)
	ar := make([]byte, 2)
	io.ReadFull(c, ar)
	if ar[1] != 0x00 {
		t.Fatalf("auth rejected: %d", ar[1])
	}

	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect failed: code %d", reply[1])
	}

	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}

	if got := resin.username(); got != "opencode.leaseA" {
		t.Fatalf("upstream saw username %q, want opencode.leaseA", got)
	}
}

// With no username the pool must still serve, picking any ready route.
func TestForwardSOCKS5AnonymousPicks(t *testing.T) {
	resin := newFakeResin(t)
	target := echoServer(t)
	proxyAddr := startForward(t, seeded(), resin.ln.Addr().String())

	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))

	// Offer no-auth as well, and take whatever the proxy selects.
	c.Write([]byte{0x05, 0x02, 0x00, 0x02})
	sel := make([]byte, 2)
	io.ReadFull(c, sel)
	if sel[1] == 0x02 {
		user := "opencode.auto"
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, 3, 't', 'o', 'k')
		c.Write(auth)
		io.ReadFull(c, make([]byte, 2))
	}

	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect failed: code %d", reply[1])
	}

	got := resin.username()
	if got != "opencode.leaseA" && got != "opencode.leaseB" {
		t.Fatalf("upstream saw username %q, want one of the seeded leases", got)
	}
}

// Exhausting the pool must fail the CONNECT, not hang.
func TestForwardFailsWhenPoolEmpty(t *testing.T) {
	resin := newFakeResin(t)
	p := seeded()
	for _, k := range []string{"leaseA", "leaseB"} {
		for i := 0; i < 2; i++ {
			p.Record(k, pool.VerdictBlocked, time.Millisecond, "")
		}
	}
	proxyAddr := startForward(t, p, resin.ln.Addr().String())

	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))

	c.Write([]byte{0x05, 0x02, 0x00, 0x02})
	io.ReadFull(c, make([]byte, 2))
	user := "opencode.auto"
	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, 3, 't', 'o', 'k')
	c.Write(auth)
	io.ReadFull(c, make([]byte, 2))

	host := "example.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0, 80)
	c.Write(req)

	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] == 0x00 {
		t.Fatal("connect should not succeed with an empty pool")
	}
}
