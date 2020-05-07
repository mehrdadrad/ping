package ping

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

var p = Ping{
	id:         rand.Intn(0xffff),
	seq:        -1,
	pSize:      64,
	ttl:        64,
	tos:        0,
	host:       "127.0.0.1",
	isV4Avail:  false,
	count:      1,
	forceV4:    false,
	forceV6:    false,
	privileged: false,
	network:    "ip",
	source:     "",
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
