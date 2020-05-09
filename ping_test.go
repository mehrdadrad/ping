package ping

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

var p = Ping{
	id:        rand.Intn(0xffff),
	seq:       -1,
	pSize:     64,
	ttl:       64,
	tos:       0,
	host:      "127.0.0.1",
	source:    "0.0.0.0",
	isV4Avail: true,
	count:     1,
	network:   "udp4",
}

func TestNew(t *testing.T) {
	_, err := New("127.0.0.1")
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

func testListen(t *testing.T) {
	conn, err := p.listen()
	if err != nil {
		t.Error(err)
	}

	a := conn.IPv4PacketConn().LocalAddr()
	if a.String() != "0.0.0.0:0" {
		t.Error("expect to have 0.0.0.0 but, ", a.String())
	}
}

func testSendRecv4(t *testing.T) {

	p, err := New("127.0.0.1")
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
		IP:   net.IP{127, 0, 0, 1},
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
		t.Error(err)
	}
}

func testSendRecv6(t *testing.T) {

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
		t.Log(err)
	}
}

func TestSetIP(t *testing.T) {
	p, err := New("127.0.0.1")
	if err != nil {
		t.Error(err)
	}

	ips := []net.IP{net.ParseIP("127.0.0.1")}

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
