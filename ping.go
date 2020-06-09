package ping

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// ProtocolIPv4ICMP is IANA ICMP IPv4
	ProtocolIPv4ICMP = 1
	// ProtocolIPv6ICMP is IANA ICMP IPv6
	ProtocolIPv6ICMP = 58
	// icmpHeaderSize is ICMP header size
	icmpHeaderSize = 8
)

// packet represents ping packet
type packet struct {
	bytes []byte
	addr  net.Addr
	ttl   int
	err   error
}

// Response represent ping response
type Response struct {
	RTT  float64
	Size int
	TTL  int
	Seq  int
	Addr string
	If   string
	Err  error
}

// Ping represents ping
type Ping struct {
	m          icmp.Message
	id         int
	seq        int
	pSize      int
	ttl        int
	tos        int
	count      int
	addr       net.Addr
	addrs      []net.IP
	ifs        map[int]string
	host       string
	isV4Avail  bool
	forceV4    bool
	forceV6    bool
	privileged bool
	network    string
	source     string
	timeout    time.Duration
	interval   time.Duration
}

// New constructs ping object
func New(host string) (*Ping, error) {
	var err error

	rand.Seed(time.Now().UnixNano())

	p := Ping{
		id:         rand.Intn(0xffff),
		seq:        -1,
		pSize:      64,
		ttl:        64,
		tos:        0,
		host:       host,
		count:      1,
		privileged: true,
	}

	// resolve host
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	p.addrs = ips

	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	p.ifs = make(map[int]string)

	p.ifs[0] = "na"
	for i := range ifs {
		p.ifs[ifs[i].Index] = ifs[i].Name
	}

	p.timeout, _ = time.ParseDuration("2s")
	p.interval, _ = time.ParseDuration("1s")

	return &p, nil
}

// SetSrcIPAddr sets the source ip address
func (p *Ping) SetSrcIPAddr(addr string) {
	p.source = addr
}

// SetCount sets the count packets
func (p *Ping) SetCount(c int) {
	p.count = c
}

// SetTTL sets the IPv4 packet TTL or IPv6 hop-limit for ICMP request packets
func (p *Ping) SetTTL(t int) {
	p.ttl = t
}

// SetPacketSize sets the ICMP packet size
func (p *Ping) SetPacketSize(s int) {
	p.pSize = s
}

// SetForceV4 sets force v4
func (p *Ping) SetForceV4() {
	p.forceV4 = true
	p.forceV6 = false
}

// SetForceV6 sets force v6
func (p *Ping) SetForceV6() {
	p.forceV4 = false
	p.forceV6 = true
}

// SetPrivilegedICMP sets privileged raw ICMP or non-privileged datagram-oriented ICMP
func (p *Ping) SetPrivilegedICMP(i bool) {
	p.privileged = i
}

// SetInterval sets wait interval between sending each packet
func (p *Ping) SetInterval(i string) error {
	interval, err := time.ParseDuration(i)
	if err != nil {
		return err
	}

	p.interval = interval

	return nil
}

// SetTimeout sets wait time for a reply for each packet sent
func (p *Ping) SetTimeout(i string) error {
	timeout, err := time.ParseDuration(i)
	if err != nil {
		return err
	}

	p.timeout = timeout

	return nil
}

// SetTOS sets type of service for each echo request packet
func (p *Ping) SetTOS(t int) error {
	if t > 255 && t < 0 {
		return fmt.Errorf("invalid tos")
	}

	p.tos = t

	return nil
}

// setIP set ip address
func (p *Ping) setIP(ips []net.IP) error {
	for _, ip := range ips {
		if !isIPv6(ip.String()) && !p.forceV6 {
			if p.privileged {
				p.addr = &net.IPAddr{IP: ip}
				p.network = "ip4:icmp"
			} else {
				p.addr = &net.UDPAddr{IP: ip, Port: 0}
				p.network = "udp4"
			}

			p.isV4Avail = true

			return nil
		} else if isIPv6(ip.String()) && !p.forceV4 {
			if p.privileged {
				p.addr = &net.IPAddr{IP: ip}
				p.network = "ip6:ipv6-icmp"
			} else {
				p.addr = &net.UDPAddr{IP: ip, Port: 0}
				p.network = "udp6"
			}

			p.isV4Avail = false

			return nil
		}
	}

	return fmt.Errorf("there is not  A or AAAA record")
}

// isIPv6 returns true if ip version is v6
func isIPv6(ip string) bool {
	return strings.Count(ip, ":") >= 2
}

// Run sends the ICMP message to destination / target
func (p *Ping) Run() (chan Response, error) {
	var (
		r    = make(chan Response, 1)
		conn *icmp.PacketConn
		err  error
	)

	if err := p.setIP(p.addrs); err != nil {
		return nil, err
	}

	if p.isV4Avail {
		if conn, err = p.listen(); err != nil {
			return nil, err
		}
	} else {
		if conn, err = p.listen(); err != nil {
			return nil, err
		}
	}

	go func() {
		for n := 0; n < p.count; n++ {
			p.ping(conn, r)
			if n != p.count-1 {
				time.Sleep(p.interval)
			}
		}
		close(r)
	}()
	return r, nil
}

// RunWithContext sends the ICMP message to destination / target with context
func (p *Ping) RunWithContext(ctx context.Context) (chan Response, error) {
	var (
		r    = make(chan Response, 1)
		conn *icmp.PacketConn
		err  error
	)

	if err := p.setIP(p.addrs); err != nil {
		return nil, err
	}

	if p.isV4Avail {
		if conn, err = p.listen(); err != nil {
			return nil, err
		}
	} else {
		if conn, err = p.listen(); err != nil {
			return nil, err
		}
	}

	go func() {
		for n := 0; n < p.count; n++ {
			select {
			case <-ctx.Done():
				conn.Close()
			default:
				p.ping(conn, r)
				if n != p.count-1 {
					time.Sleep(p.interval)
				}
			}
		}
		close(r)
	}()

	return r, nil
}

// listen starts to listen incoming icmp
func (p *Ping) listen() (*icmp.PacketConn, error) {
	c, err := icmp.ListenPacket(p.network, p.source)
	if err != nil {
		return c, err
	}
	return c, nil
}

// recv4 reads icmp message for IPv4
func (p *Ping) recv4(conn *icmp.PacketConn, rcvdChan chan<- Response) {
	var (
		err              error
		src              net.Addr
		ts               = time.Now()
		ifName           string
		n, ttl, icmpType int
	)

	bytes := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(p.timeout))

	for {
		var cm *ipv4.ControlMessage
		n, cm, src, err = conn.IPv4PacketConn().ReadFrom(bytes)
		if cm != nil {
			ttl = cm.TTL
			ifName = p.ifs[cm.IfIndex]
		} else {
			ifName = "na"
		}

		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					err = errors.New("Request timeout")
				}
			}
		}

		bytes = bytes[:n]

		if n > 0 {
			icmpType = int(bytes[0])
		}

		switch icmpType {
		case int(ipv4.ICMPTypeTimeExceeded):
			if n >= 28 && p.isMyReply(bytes) {
				err = errors.New("Time exceeded")
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, If: ifName, Err: err}
				return
			}
		case int(ipv4.ICMPTypeEchoReply):
			if n >= 8 && p.isMyEchoReply(bytes) {
				rtt := float64(time.Now().UnixNano()-getTimeStamp(bytes[8:])) / 1000000
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, RTT: rtt, If: ifName, Err: err}
				return
			}
		case int(ipv4.ICMPTypeDestinationUnreachable):
			if n >= 28 && p.isMyReply(bytes) {
				err = errors.New(unreachableMessage(bytes))
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, If: ifName, Err: err}
				return
			}
		case int(ipv4.ICMPTypeRedirect):
			if n >= 28 && p.isMyReply(bytes) {
				err = errors.New(redirectMessage(bytes))
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, If: ifName, Err: err}
				return
			}
		default:
			// TODO
		}

		if time.Since(ts) < p.timeout {
			continue
		}

		err = errors.New("Request timeout")
		rcvdChan <- Response{Addr: p.getIPAddr(src), Seq: p.seq, Err: err}
		break
	}
}

// recv6 reads icmp message for IPv6
func (p *Ping) recv6(conn *icmp.PacketConn, rcvdChan chan<- Response) {
	var (
		err              error
		src              net.Addr
		ts               = time.Now()
		ifName           string
		n, ttl, icmpType int
	)

	bytes := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(p.timeout))

	for {
		var cm *ipv6.ControlMessage
		n, cm, src, err = conn.IPv6PacketConn().ReadFrom(bytes)
		if cm != nil {
			ttl = cm.HopLimit
			ifName = p.ifs[cm.IfIndex]
		} else {
			ifName = "na"
		}

		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					err = errors.New("Request timeout")
				}
			}
		}

		bytes = bytes[:n]

		if n > 0 {
			icmpType = int(bytes[0])
		}

		switch icmpType {
		case int(ipv6.ICMPTypeTimeExceeded):
			if n >= 48 && p.isMyReply(bytes) {
				err = errors.New("Time exceeded")
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, If: ifName, Err: err}
				return
			}
		case int(ipv6.ICMPTypeEchoReply):
			if n >= 8 && p.isMyEchoReply(bytes) {
				rtt := float64(time.Now().UnixNano()-getTimeStamp(bytes[8:])) / 1000000
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, RTT: rtt, If: ifName, Err: err}
				return
			}
		case int(ipv6.ICMPTypeDestinationUnreachable):
			if n >= 48 && p.isMyReply(bytes) {
				err = errors.New(unreachableMessage(bytes))
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, If: ifName, Err: err}
				return
			}
		case int(ipv6.ICMPTypeRedirect):
			if n >= 48 && p.isMyReply(bytes) {
				err = errors.New(redirectMessage(bytes))
				rcvdChan <- Response{Addr: p.getIPAddr(src), TTL: ttl, Seq: p.seq, Size: p.pSize, If: ifName, Err: err}
				return
			}
		default:
			// TODO
		}

		if time.Since(ts) < p.timeout {
			continue
		}

		err = errors.New("Request timeout")
		rcvdChan <- Response{Addr: p.getIPAddr(src), Seq: p.seq, Err: err}
		break
	}
}

func (p *Ping) send(conn *icmp.PacketConn) error {
	var (
		icmpType icmp.Type
		err      error
	)

	if isIPv6(p.addr.String()) {
		icmpType = ipv6.ICMPTypeEchoRequest
		conn.IPv6PacketConn().SetHopLimit(p.ttl)
		conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
		conn.IPv6PacketConn().SetControlMessage(ipv6.FlagInterface, true)

	} else {
		icmpType = ipv4.ICMPTypeEcho
		conn.IPv4PacketConn().SetTTL(p.ttl)
		conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
		conn.IPv4PacketConn().SetTOS(p.tos)
		conn.IPv4PacketConn().SetControlMessage(ipv4.FlagInterface, true)
	}

	p.seq++
	bytes, err := (&icmp.Message{
		Type: icmpType, Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  p.seq,
			Data: p.payload(time.Now().UnixNano()),
		},
	}).Marshal(nil)
	if err != nil {
		return err
	}

	for range []int{0, 1} {
		if _, err = conn.WriteTo(bytes, p.addr); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		break
	}

	return err
}

func (p *Ping) payload(ts int64) []byte {
	data := make([]byte, 8)
	n := icmpHeaderSize + 8

	// add timestamp
	for i := uint8(0); i < 8; i++ {
		data[i] = byte((ts >> (i * 8)) & 0xff)
	}

	// add id if privileged icmp
	if !p.privileged {
		id := make([]byte, 2)
		for i := uint8(0); i < 2; i++ {
			id[i] = byte((int16(p.id) >> (i * 8)) & 0xff)
		}
		data = append(data, id...)
		n += 2
	}

	payload := make([]byte, p.pSize-n)
	return append(data, payload...)
}

// ping sends and receives an ICMP packet
func (p *Ping) ping(conn *icmp.PacketConn, resp chan Response) {
	if err := p.send(conn); err != nil {
		resp <- Response{Err: err, Addr: p.getIPAddr(p.addr), Seq: p.seq, Size: p.pSize}
	} else {
		if p.isV4Avail {
			p.recv4(conn, resp)
		} else {
			p.recv6(conn, resp)
		}
	}
}

func (p *Ping) isMyReply(bytes []byte) bool {
	var n = 28

	if !p.isV4Avail {
		n = 48
	}

	respID := int(bytes[n+4])<<8 | int(bytes[n+5])
	respSq := int(bytes[n+6])<<8 | int(bytes[n+7])

	if p.id == respID && p.seq == respSq {
		return true
	}

	return false
}

func (p *Ping) isMyEchoReply(bytes []byte) bool {
	var respID int

	if p.privileged {
		respID = int(bytes[4])<<8 | int(bytes[5])
	} else {
		respID = int(bytes[17])<<8 | int(bytes[16])
	}

	respSq := int(bytes[6])<<8 | int(bytes[7])
	if respID == p.id && respSq == p.seq {
		return true
	}

	return false
}

func (p *Ping) getIPAddr(a net.Addr) string {
	switch a.(type) {
	case *net.UDPAddr:
		h, _, err := net.SplitHostPort(a.String())
		if err != nil {
			return "na"
		}
		return h
	case *net.IPAddr:
		return a.String()
	}

	h, _, err := net.SplitHostPort(p.addr.String())
	if err != nil {
		return "na"
	}
	return h
}

func getTimeStamp(m []byte) int64 {
	var ts int64
	for i := uint(0); i < 8; i++ {
		ts += int64(m[i]) << (i * 8)
	}
	return ts
}

func unreachableMessage(bytes []byte) string {
	code := int(bytes[1])
	mtu := int(bytes[6])<<8 | int(bytes[7])
	var errors = []string{
		"Network unreachable",
		"Host unreachable",
		"Protocol unreachable",
		"Port unreachable",
		fmt.Sprintf("The datagram is too big - next-hop MTU: %d", mtu),
		"Source route failed",
		"Destination network unknown",
		"Destination host unknown",
		"Source host isolated",
		"The destination network is administratively prohibited",
		"The destination host is administratively prohibited",
		"The network is unreachable for Type Of Service",
		"The host is unreachable for Type Of Service",
		"Communication administratively prohibited",
		"Host precedence violation",
		"Precedence cutoff in effect",
	}

	return errors[code]
}

func redirectMessage(bytes []byte) string {
	code := int(bytes[1])
	var errors = []string{
		"Redirect for Network",
		"Redirect for Host",
		"Redirect for Type of Service and Network",
		"Redirect for Type of Service and Host",
	}

	return errors[code]
}
