package ping

import (
	"math/rand"
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

func TestGetTimeStamp(t *testing.T) {
	ts1 := time.Now().UnixNano()
	pl := p.payload(ts1)
	ts2 := getTimeStamp(pl)
	t.Log(ts1, ts2)
}
