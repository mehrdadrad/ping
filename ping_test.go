package ping

import (
	"math/rand"
	"net"
	"os"
	"testing"
	"time"
)

var (
	HostV4 = getEnvHostV4()
	HostV6 = getEnvHostV6()

	p = Ping{
		id:        rand.Intn(0xffff),
		seq:       -1,
		pSize:     64,
		ttl:       64,
		tos:       0,
		host:      HostV4,
		source:    "0.0.0.0",
		isV4Avail: true,
		count:     1,
		network:   "udp4",
	}
)

func TestNew(t *testing.T) {
	_, err := New(HostV4)
	if err != nil {
		t.Error("New failed:", err)
	}
}

func TestGetTimeStamp(t *testing.T) {
	ts1 := time.Now().UnixNano()
	pl := p.payload(ts1)
	ts2 := getTimeStamp(pl)
	if ts1 != ts2 {
		t.Error("timestamp failed")
	}
}

func TestGetIPAddr(t *testing.T) {
	i := net.UDPAddr{
		IP:   net.ParseIP("192.168.10.1"),
		Port: 1000,
	}

	o := p.getIPAddr(&i)

	if o != "192.168.10.1" {
		t.Error("getIPAddr UDPAdd failed")
	}

	ii := net.IPAddr{
		IP: net.ParseIP("192.168.10.1"),
	}

	o = p.getIPAddr(&ii)

	if o != "192.168.10.1" {
		t.Error("getIPAddr UDPAdd failed")
	}
}

func TestListen(t *testing.T) {
	conn, err := p.listen()
	if err != nil {
		t.Error(err)
	}

	a := conn.IPv4PacketConn().LocalAddr()
	if a.String() != "0.0.0.0:0" {
		t.Error("expect to have 0.0.0.0 but, ", a.String())
	}
}

func TestSendRecv4(t *testing.T) {

	p, err := New(HostV4)
	if err != nil {
		t.Error(err)
	}

	p.privileged = false
	p.network = "udp4"

	conn, err := p.listen()
	if err != nil {
		t.Error(err)
	}

	p.addr = &net.UDPAddr{
		IP:   net.ParseIP(HostV4),
		Port: 0,
	}

	err = p.send(conn)
	if err != nil {
		t.Error(err)
	}

	rc := make(chan Response, 1)
	p.recv4(conn, rc)
	r := <-rc

	if r.Err != nil {
		t.Error(r.Err)
	}
}

func TestSendRecv6(t *testing.T) {

	p, err := New("::1")
	if err != nil {
		t.Error(err)
	}

	p.privileged = false
	p.network = "udp6"

	conn, err := p.listen()
	if err != nil {
		t.Error(err)
	}

	p.addr = &net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 0,
	}

	err = p.send(conn)
	if err != nil {
		t.Error(err)
	}

	rc := make(chan Response, 1)
	p.recv6(conn, rc)
	r := <-rc

	if r.Err != nil {
		t.Error(r.Err)
	}
}

func TestSetIP(t *testing.T) {
	p, err := New(HostV4)
	if err != nil {
		t.Error(err)
	}

	ips := []net.IP{net.ParseIP(HostV4)}

	p.privileged = true
	p.setIP(ips)
	if p.network != "ip4:icmp" {
		t.Error("expected ip4:icmp but got", p.network)
	}

	p.privileged = false
	p.setIP(ips)
	if p.network != "udp4" {
		t.Error("expected udp4 but got", p.network)
	}
}

func TestSetIP6(t *testing.T) {
	p, err := New("::1")
	if err != nil {
		t.Error(err)
	}

	ips := []net.IP{net.ParseIP("::1")}

	p.privileged = true
	p.setIP(ips)
	if p.network != "ip6:ipv6-icmp" {
		t.Error("expected ip6:icmp but got", p.network)
	}

	p.privileged = false
	p.setIP(ips)
	if p.network != "udp6" {
		t.Error("expected udp6 but got", p.network)
	}
}

func TestSetSrcIPAddr(t *testing.T) {
	p.SetSrcIPAddr(HostV4)
	if p.source != HostV4 {
		t.Error("expected source 127.0.0.1 but got,", p.source)
	}
}

func TestSetInterval(t *testing.T) {
	err := p.SetInterval("2s")
	if err != nil {
		t.Error("unexpected error", err)
	}
	if p.interval != time.Second*2 {
		t.Error("expected 2s interval but got", p.interval.String())
	}

	err = p.SetInterval("2")
	if err == nil {
		t.Error("expected to have error but nothing")
	}
}

func TestUnreachableMessage(t *testing.T) {

	msg := unreachableMessage([]byte{0, 3, 0, 0, 0, 0, 0, 0})
	if msg != "Port unreachable" {
		t.Error("expected to get Port unreachable but got,", msg)
	}
}

func TestIsMyEchoReply(t *testing.T) {
	p.seq = 0
	p.id = 8247
	data := []byte{0x0, 0x0, 0xe9, 0xd, 0x20, 0x37, 0x0, 0x0, 0xb8,
		0x20, 0xfb, 0xa1, 0xf5, 0xc1, 0x16, 0x16, 0x37, 0x20}
	if ok := p.isMyEchoReply(data); !ok {
		t.Error("expected to get true but got false")
	}

	p.privileged = true
	if ok := p.isMyEchoReply(data); !ok {
		t.Error("expected to get true but got false")
	}

}

func TestRun(t *testing.T) {
	p1, err := New(HostV4)
	if err != nil {
		t.Fatal(err)
	}

	p1.SetPrivilegedICMP(false)
	p1.SetCount(1)

	r, err := p1.Run()
	if err != nil {
		t.Fatal(err)
	}

	result := <-r
	if result.Err != nil {
		t.Fatal(result.Err)
	}

	if result.Addr != HostV4 {
		t.Errorf("expect addr : %s but got %s", HostV4, result.Addr)
	}
}

func getEnvHostV4() string {
	h := os.Getenv("PING_HOST_V4")
	if len(h) > 0 {
		return h
	}

	return "127.0.0.1"
}

func getEnvHostV6() string {
	h := os.Getenv("PING_HOST_V6")
	if len(h) > 0 {
		return h
	}

	return "::1"
}
