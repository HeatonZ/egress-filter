// SOCKS5 and HTTP CONNECT forward proxy in one listener.
//
// Callers that speak a forward proxy give us no URL path to put an account in,
// so the account travels in the proxy credentials instead: the SOCKS5 username
// (or the Proxy-Authorization user for CONNECT) is read as a preferred lease.
// When it is absent or unhealthy the pool picks, which is what lets a client
// keep a single static proxy entry and still fail over.
package entry

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HeatonZ/egress-filter/internal/pool"
)

// Forward serves SOCKS5 and HTTP CONNECT on one port.
type Forward struct {
	Pool *pool.Pool
	Log  *slog.Logger

	// Upstream is Resin's forward-proxy endpoint, host:port.
	Upstream string
	// Token is appended as the SOCKS5 password.
	Token string
	// Password is this entry's own password. When set, clients must present it;
	// it is separate from the per-instance Resin tokens in Upstreams.
	Password string
	// Upstreams maps a route's upstream name to that instance's endpoint and
	// token, so several Resin deployments can sit behind one entry.
	Upstreams Upstreams
	// Platform prefixes the account: the upstream user is "platform.account".
	Platform string
	// DialTimeout bounds the hop to the upstream proxy.
	DialTimeout time.Duration
}

// Serve accepts connections until the listener closes.
func (f *Forward) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			// A single bad accept should not kill the listener.
			f.Log.Warn("forward accept", "error", err)
			continue
		}
		go f.handle(c)
	}
}

func (f *Forward) handle(c net.Conn) {
	defer c.Close()

	// One read ahead decides the protocol: SOCKS5 always starts with 0x05,
	// while CONNECT starts with a method name.
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		f.handleSOCKS5(c, br)
		return
	}
	f.handleHTTP(c, br)
}

func (f *Forward) handleSOCKS5(c net.Conn, br *bufio.Reader) {
	// Greeting: VER, NMETHODS, METHODS.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	wantUserPass := false
	for _, m := range methods {
		if m == 0x02 {
			wantUserPass = true
			break
		}
	}
	method := byte(0x00)
	if wantUserPass {
		method = 0x02
	}
	if f.Password != "" && !wantUserPass {
		// A configured password means credentials are mandatory. Offering
		// no-auth to a client that never mentions it would let anyone who omits
		// the method skip authentication entirely: RFC 1928 lets the client
		// choose, so the server has to refuse rather than fall back.
		_, _ = c.Write([]byte{0x05, 0xff})
		return
	}
	if _, err := c.Write([]byte{0x05, method}); err != nil {
		return
	}

	preferred := ""
	if method == 0x02 {
		// Auth: VER, ULEN, UNAME, PLEN, PASSWD.
		ah := make([]byte, 2)
		if _, err := io.ReadFull(br, ah); err != nil || ah[0] != 0x01 {
			return
		}
		uname := make([]byte, int(ah[1]))
		if _, err := io.ReadFull(br, uname); err != nil {
			return
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(br, pl); err != nil {
			return
		}
		passwd := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(br, passwd); err != nil {
			return
		}
		preferred = string(uname)
		if !f.authorized(string(passwd)) {
			// RFC 1929 auth failure: the client learns the credential is wrong
			// instead of seeing an unexplained connect failure.
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT.
	rh := make([]byte, 4)
	if _, err := io.ReadFull(br, rh); err != nil || rh[0] != 0x05 {
		return
	}
	if rh[1] != 0x01 { // CONNECT only
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	host, err := readAddr(br, rh[3])
	if err != nil {
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBuf))))

	f.tunnel(c, br, target, preferred, func(net.Conn) error {
		_, werr := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return werr
	}, func() {
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	})
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	}
	return "", fmt.Errorf("unsupported address type %d", atyp)
}

func (f *Forward) handleHTTP(c net.Conn, br *bufio.Reader) {
	// A CONNECT request is a single head; read it without consuming the tunnel.
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	preferred := ""
	if u, p, ok := parseProxyAuth(req.Header.Get("Proxy-Authorization")); ok {
		if !f.authorized(p) {
			writeProxyAuthRequired(c)
			return
		}
		preferred = u
	} else if f.Password != "" {
		writeProxyAuthRequired(c)
		return
	}

	if req.Method != http.MethodConnect {
		// Plain absolute-URI proxying is not supported: nothing in this
		// deployment needs it, and silently mishandling it would be worse than a
		// clear error.
		fmt.Fprint(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}

	f.tunnel(c, br, req.Host, preferred, func(net.Conn) error {
		_, werr := fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		return werr
	}, func() {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	})
}

// tunnel opens the upstream hop and then splices bytes both ways.
func (f *Forward) tunnel(c net.Conn, br *bufio.Reader, target, preferred string,
	onSuccess func(net.Conn) error, onFailure func()) {

	route, account := f.choose(preferred)
	if account == "" {
		onFailure()
		return
	}

	upstream, err := f.dialUpstream(route, target)
	if err != nil {
		f.Log.Warn("forward dial", "route", account, "target", target, "error", err)
		f.Pool.Record(route.Key, pool.VerdictUnknown, 0, "forward dial: "+err.Error())
		onFailure()
		return
	}
	defer upstream.Close()

	if err := onSuccess(upstream); err != nil {
		return
	}

	// The client may have pipelined bytes behind the handshake; they are still
	// sitting in br and must be forwarded.
	if n := br.Buffered(); n > 0 {
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		if _, err := upstream.Write(buf); err != nil {
			return
		}
	}

	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			c.Close()
			upstream.Close()
		})
	}

	go func() {
		_, _ = io.Copy(upstream, c)
		closeBoth()
	}()
	_, _ = io.Copy(c, upstream)
	closeBoth()
}

func (f *Forward) choose(preferred string) (pool.Route, string) {
	if route, ok := PinRoute(f.Upstreams, preferred); ok {
		// Same rule as the reverse entry: the caller decides the lease, Resin
		// creates it on demand, so discovery is not a precondition.
		route = f.Pool.Ensure(route)
		if f.Pool.Blocked(route.Key) {
			return pool.Route{}, ""
		}
		return route, route.Key
	}
	route, ok := f.Pool.Pick()
	if !ok {
		return pool.Route{}, ""
	}
	return route, route.Key
}

// dialUpstream performs a SOCKS5 CONNECT to Resin, which then binds a lease.
func (f *Forward) dialUpstream(route pool.Route, target string) (net.Conn, error) {
	timeout := f.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	backend, token := f.Upstream, f.Token
	if up, ok := f.Upstreams.Resolve(route.Upstream); ok {
		if up.ProxyAddr != "" {
			backend = up.ProxyAddr
		}
		if up.Token != "" {
			token = up.Token
		}
	}
	conn, err := net.DialTimeout("tcp", backend, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	user := f.Platform + "." + route.Lease
	// Offer no-auth and user/pass so the upstream can pick; Resin requires
	// credentials, but offering both avoids a second round trip on the happy
	// path.
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		conn.Close()
		return nil, err
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		conn.Close()
		return nil, err
	}
	if sel[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("upstream is not socks5")
	}
	switch sel[1] {
	case 0x00:
		// no auth
	case 0x02:
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(token)))
		auth = append(auth, token...)
		if _, err := conn.Write(auth); err != nil {
			conn.Close()
			return nil, err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			conn.Close()
			return nil, err
		}
		if ar[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("upstream rejected credentials")
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("upstream selected unsupported auth method %d", sel[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		// Domain names are forwarded as-is, so the upstream resolves them. That
		// matters: resolving here would leak DNS outside the proxy and pin a
		// stale address across a CDN.
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("upstream connect failed: code %d", reply[1])
	}
	if _, err := readAddr(conn, reply[3]); err != nil {
		conn.Close()
		return nil, err
	}
	bt := make([]byte, 2)
	if _, err := io.ReadFull(conn, bt); err != nil {
		conn.Close()
		return nil, err
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// normalisePreferred accepts either a bare account or a platform.account user,
// because callers configured against Resin today already write the latter.
func normalisePreferred(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.IndexByte(u, '.'); i > 0 {
		return u[i+1:]
	}
	return u
}

func parseProxyAuth(h string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	s := string(raw)
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return s, "", true
	}
	return s[:i], s[i+1:], true
}

var _ = context.Background

// authorized reports whether pass is this entry's own password. An empty
// configured password leaves the entry open, which is only useful for tests.
func (f *Forward) authorized(pass string) bool {
	return f.Password == "" || pass == f.Password
}

// writeProxyAuthRequired answers a CONNECT with 407. Line endings are assembled
// from byte values so they cannot be mangled by an editor.
func writeProxyAuthRequired(c net.Conn) {
	crlf := string([]byte{13, 10})
	quote := string([]byte{34})
	_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required"+crlf+
		"Proxy-Authenticate: Basic realm="+quote+"egress-filter"+quote+crlf+
		"Content-Length: 0"+crlf+crlf)
}
