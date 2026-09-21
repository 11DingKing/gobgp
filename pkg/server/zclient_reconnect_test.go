// Copyright (C) 2026 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/zebra"
)

// ZAPI commands on the wire for v6/frr8.2 (commands below the version
// conversion threshold are sent as-is, see minDifferentAPIType).
const (
	fakeCmdInterfaceAdd    uint16 = 0
	fakeCmdRedistributeAdd uint16 = 11
)

// fakeZebraConn records the ZAPI commands that one accepted connection
// receives.
type fakeZebraConn struct {
	id   int
	conn net.Conn

	mu       sync.Mutex
	closed   bool
	messages [][]byte
	commands []uint16
}

func (c *fakeZebraConn) record(msg []byte, command uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.messages = append(c.messages, msg)
	c.commands = append(c.commands, command)
}

func (c *fakeZebraConn) snapshot() ([]uint16, [][]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.commands), slices.Clone(c.messages)
}

func (c *fakeZebraConn) hasCommand(command uint16) bool {
	cmds, _ := c.snapshot()
	return slices.Contains(cmds, command)
}

func (c *fakeZebraConn) commandCount(command uint16) int {
	cmds, _ := c.snapshot()
	n := 0
	for _, v := range cmds {
		if v == command {
			n++
		}
	}
	return n
}

// routeAddContains reports whether any ROUTE_ADD message carries the given
// IPv4 prefix bytes.
func (c *fakeZebraConn) routeAddContains(prefix [4]byte) bool {
	_, msgs := c.snapshot()
	want := prefix[:]
	for _, msg := range msgs {
		if len(msg) < 10 {
			continue
		}
		command := binary.BigEndian.Uint16(msg[8:10])
		if command != uint16(zebra.RouteAdd.ToEach(zebra.MaxZapiVer, zebra.NewSoftware(zebra.MaxZapiVer, "frr8.2"))) {
			continue
		}
		if bytesContains(msg, want) {
			return true
		}
	}
	return false
}

func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if slices.Equal(haystack[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// fakeZebra is a minimal ZAPI v6 server: it greets every accepted connection
// (unblocking the client's initial protocol exchange) and records all received
// commands.
type fakeZebra struct {
	t  *testing.T
	ln net.Listener

	mu    sync.Mutex
	conns []*fakeZebraConn
}

func newFakeZebra(t *testing.T) *fakeZebra {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeZebra{t: t, ln: ln}
	go f.serve()
	return f
}

func (f *fakeZebra) addr() string {
	return f.ln.Addr().String()
}

func (f *fakeZebra) url() string {
	return "tcp:" + f.addr()
}

func (f *fakeZebra) serve() {
	id := 0
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		c := &fakeZebraConn{id: id, conn: conn}
		id++
		f.mu.Lock()
		f.conns = append(f.conns, c)
		f.mu.Unlock()
		go f.handle(c)
	}
}

// helloReply builds a ZAPI v6 HELLO response (frr8.2 layout).
func helloReply() []byte {
	msg := make([]byte, 10+9)
	binary.BigEndian.PutUint16(msg[0:2], uint16(len(msg)))
	msg[2] = zebra.HeaderMarker(zebra.MaxZapiVer) // FRR marker
	msg[3] = zebra.MaxZapiVer
	binary.BigEndian.PutUint32(msg[4:8], 0)
	binary.BigEndian.PutUint16(msg[8:10], uint16(zebra.Hello))
	body := msg[10:]
	body[0] = uint8(zebra.RouteBGP) // redistDefault
	// instance(2), sessionID(4), receiveNotify(1), synchronous(1) stay zero
	return msg
}

func (f *fakeZebra) handle(c *fakeZebraConn) {
	defer c.conn.Close()
	// Greet first so the client's blocking first-message read completes.
	if _, err := c.conn.Write(helloReply()); err != nil {
		return
	}
	header := make([]byte, 10)
	for {
		if _, err := io.ReadFull(c.conn, header); err != nil {
			c.mu.Lock()
			c.closed = true
			c.mu.Unlock()
			return
		}
		msgLen := binary.BigEndian.Uint16(header[0:2])
		if int(msgLen) < len(header) {
			return
		}
		msg := make([]byte, msgLen)
		copy(msg, header)
		if _, err := io.ReadFull(c.conn, msg[len(header):]); err != nil {
			return
		}
		command := binary.BigEndian.Uint16(header[8:10])
		c.record(msg, command)
	}
}

func (f *fakeZebra) conn(i int) *fakeZebraConn {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < len(f.conns) {
		return f.conns[i]
	}
	return nil
}

func (f *fakeZebra) connCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.conns)
}

// closeConn drops the given connection from the server side, simulating a
// Zebra/zserv restart.
func (f *fakeZebra) closeConn(i int) {
	if c := f.conn(i); c != nil {
		_ = c.conn.Close()
	}
}

func (f *fakeZebra) close() {
	_ = f.ln.Close()
	f.mu.Lock()
	for _, c := range f.conns {
		_ = c.conn.Close()
	}
	f.mu.Unlock()
}

func startBgpServerWithZebra(t *testing.T, zcURL string) (*BgpServer, *zebraClient) {
	t.Helper()
	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65000,
			RouterId:   "1.1.1.1",
			ListenPort: -1,
		},
	}))
	t.Cleanup(func() {
		_ = s.StopBgp(context.Background(), &api.StopBgpRequest{})
	})

	require.NoError(t, s.EnableZebra(context.Background(), &api.EnableZebraRequest{
		Url:        zcURL,
		RouteTypes: []string{"static"},
		Version:    uint32(zebra.MaxZapiVer),
		// MPLS/NHT stay disabled: first-connection behavior must be unchanged.
		SoftwareName: "frr8.2",
	}))
	require.NotNil(t, s.zclient)
	return s, s.zclient
}

func addLocalRoute(t *testing.T, s *BgpServer, prefix string, nexthop string) {
	t.Helper()
	panh, err := bgp.NewPathAttributeNextHop(netip.MustParseAddr(nexthop))
	require.NoError(t, err)
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		panh,
	}
	nlri, err := bgp.NewIPAddrPrefix(netip.MustParsePrefix(prefix))
	require.NoError(t, err)
	path, err := apiutil.NewPath(bgp.RF_IPv4_UC, nlri, false, attrs, time.Now())
	require.NoError(t, err)
	_, err = s.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{mustApi2apiutilPath(path)}})
	require.NoError(t, err)
}

// TestZebraClient_ReconnectAndReplay verifies that after the Zebra connection
// drops, gobgpd establishes a brand new session, redoes interface/redistribute
// subscriptions and replays the current RIB routes, instead of spinning on the
// closed receive channel or leaving Zebra with stale half-state.
func TestZebraClient_ReconnectAndReplay(t *testing.T) {
	fake := newFakeZebra(t)
	defer fake.close()

	s, zc := startBgpServerWithZebra(t, fake.url())

	// First session: negotiation, interface add and redistribute subscription.
	require.Eventually(t, func() bool {
		c := fake.conn(0)
		return c != nil && c.hasCommand(fakeCmdInterfaceAdd) &&
			c.commandCount(fakeCmdRedistributeAdd) >= 1
	}, 5*time.Second, 10*time.Millisecond, "first session was not established")
	require.Eventually(t, zc.isHealthy, 5*time.Second, 10*time.Millisecond,
		"first session must be reported healthy (NHT/MPLS disabled)")

	// Install a route while connected; it must be sent to the first session.
	addLocalRoute(t, s, "10.10.0.0/24", "10.0.0.1")
	var prefix [4]byte
	copy(prefix[:], []byte{10, 10, 0, 0})
	require.Eventually(t, func() bool {
		c := fake.conn(0)
		return c != nil && c.routeAddContains(prefix)
	}, 5*time.Second, 10*time.Millisecond, "route was not installed into the first Zebra session")

	// Zebra/zserv restarts: drop the connection from the server side.
	fake.closeConn(0)

	// A second session must be established and re-subscribed.
	require.Eventually(t, func() bool {
		c := fake.conn(1)
		return c != nil && c.hasCommand(fakeCmdInterfaceAdd) &&
			c.commandCount(fakeCmdRedistributeAdd) >= 1
	}, 10*time.Second, 10*time.Millisecond, "second session was not established after disconnect")

	// The current GoBGP RIB must be replayed into the new session.
	require.Eventually(t, func() bool {
		c := fake.conn(1)
		return c != nil && c.routeAddContains(prefix)
	}, 5*time.Second, 10*time.Millisecond, "route was not replayed into the new Zebra session")
	require.Eventually(t, zc.isHealthy, 5*time.Second, 10*time.Millisecond,
		"reconnected session must be reported healthy")

	// Stopping BGP must terminate dialing/backoff/replay immediately and not
	// trigger any further session.
	connCount := fake.connCount()
	done := make(chan struct{})
	go func() {
		zc.wait()
		close(done)
	}()
	require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("zebra loop goroutine did not exit after StopBgp")
	}
	// No new connection may be opened after stopping BGP.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		assert.Equal(t, connCount, fake.connCount())
	}
}

// TestZebraClient_StopDuringBackoff verifies that stopping while Zebra is
// unreachable cancels the in-flight dial/backoff immediately instead of
// waiting for the retry timer.
func TestZebraClient_StopDuringBackoff(t *testing.T) {
	// Grab a free address and release it so Dial fails immediately with
	// ECONNREFUSED, leaving the loop in its backoff wait.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	url := "tcp:" + ln.Addr().String()
	require.NoError(t, ln.Close())

	s := NewBgpServer()
	go s.Serve()
	require.NoError(t, s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{Asn: 65000, RouterId: "1.1.1.1", ListenPort: -1},
	}))

	// EnableZebra must succeed even though Zebra is not reachable: connection
	// establishment runs in the background with retry.
	require.NoError(t, s.EnableZebra(context.Background(), &api.EnableZebraRequest{
		Url:          url,
		RouteTypes:   []string{"static"},
		Version:      uint32(zebra.MaxZapiVer),
		SoftwareName: "frr8.2",
	}))
	zc := s.zclient
	require.NotNil(t, zc)
	require.False(t, zc.isHealthy(), "a session that never connected must not look healthy")

	// Let the first immediate dial round fail and enter backoff.
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	require.NoError(t, s.StopBgp(context.Background(), &api.StopBgpRequest{}))
	elapsed := time.Since(start)
	// The canceled backoff (1s) must not be waited out.
	assert.Less(t, elapsed, 750*time.Millisecond, "StopBgp blocked on the uncanceled backoff: %v", elapsed)

	select {
	case <-zc.done:
	case <-time.After(2 * time.Second):
		t.Fatal("zebra loop goroutine did not exit after StopBgp during backoff")
	}
}

// TestZebraDialBackoff checks the exponential, capped backoff policy.
func TestZebraDialBackoff(t *testing.T) {
	assert.Equal(t, zebraDialInitialBackoff, nextDialBackoff(0))
	assert.Equal(t, 2*time.Second, nextDialBackoff(time.Second))
	assert.Equal(t, 4*time.Second, nextDialBackoff(2*time.Second))
	assert.Equal(t, zebraDialMaxBackoff, nextDialBackoff(zebraDialMaxBackoff))
	assert.Equal(t, zebraDialMaxBackoff, nextDialBackoff(zebraDialMaxBackoff*2))

	for d := zebraDialInitialBackoff; d < zebraDialMaxBackoff; d = nextDialBackoff(d) {
		j := jitterBackoff(d)
		assert.GreaterOrEqual(t, j, d)
		assert.LessOrEqual(t, j, d+d/zebraBackoffJitterDenominator)
	}
	j := jitterBackoff(zebraDialMaxBackoff)
	assert.GreaterOrEqual(t, j, zebraDialMaxBackoff)
	assert.LessOrEqual(t, j, zebraDialMaxBackoff+zebraDialMaxBackoff/zebraBackoffJitterDenominator)
}

// TestZebraBackoffCancelable verifies that an active backoff wait is
// interrupted immediately when the integration is stopped.
func TestZebraBackoffCancelable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	z := &zebraClient{ctx: ctx}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	ok := z.waitBackoff(time.Minute)
	assert.False(t, ok)
	assert.Less(t, time.Since(start), time.Second)
}
