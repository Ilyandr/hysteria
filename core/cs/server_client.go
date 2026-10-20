package cs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/acl"
	"github.com/apernet/hysteria/core/transport"
	"github.com/apernet/hysteria/core/utils"
	"github.com/lunixbochs/struc"
	"github.com/quic-go/quic-go"
)

const udpBufferSize = 4096

type serverClient struct {
	CC              quic.Connection
	Transport       *transport.ServerTransport
	Auth            []byte
	AuthLabel       string // Base64 encoded auth
	DisableUDP      bool
	ACLEngine       *acl.Engine
	CTCPRequestFunc TCPRequestFunc
	CTCPErrorFunc   TCPErrorFunc
	CUDPRequestFunc UDPRequestFunc
	CUDPErrorFunc   UDPErrorFunc

	TrafficCounter TrafficCounter

	udpSessionMutex  sync.RWMutex
	udpSessionMap    map[uint32]transport.STPacketConn
	nextUDPSessionID uint32
	udpDefragger     defragger
}

func newServerClient(cc quic.Connection, tr *transport.ServerTransport, auth []byte, disableUDP bool, ACLEngine *acl.Engine,
	CTCPRequestFunc TCPRequestFunc, CTCPErrorFunc TCPErrorFunc,
	CUDPRequestFunc UDPRequestFunc, CUDPErrorFunc UDPErrorFunc,
	TrafficCounter TrafficCounter,
) *serverClient {
	sc := &serverClient{
		CC:              cc,
		Transport:       tr,
		Auth:            auth,
		AuthLabel:       base64.StdEncoding.EncodeToString(auth),
		DisableUDP:      disableUDP,
		ACLEngine:       ACLEngine,
		CTCPRequestFunc: CTCPRequestFunc,
		CTCPErrorFunc:   CTCPErrorFunc,
		CUDPRequestFunc: CUDPRequestFunc,
		CUDPErrorFunc:   CUDPErrorFunc,
		TrafficCounter:  TrafficCounter,
		udpSessionMap:   make(map[uint32]transport.STPacketConn),
	}
	return sc
}

func (c *serverClient) ClientAddr() net.Addr {
	// quic.Connection's remote address may change since we have connection migration now,
	// so logs need to dynamically get the remote address every time.
	return c.CC.RemoteAddr()
}

func (c *serverClient) Run() error {
	if !c.DisableUDP {
		go func() {
			for {
				msg, err := c.CC.ReceiveMessage()
				if err != nil {
					break
				}
				c.handleMessage(msg)
			}
		}()
	}
	for {
		stream, err := c.CC.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		if c.TrafficCounter != nil {
			c.TrafficCounter.IncConn(c.AuthLabel)
		}
		go func() {
			stream := &qStream{stream}
			c.handleStream(stream)
			_ = stream.Close()
			if c.TrafficCounter != nil {
				c.TrafficCounter.DecConn(c.AuthLabel)
			}
		}()
	}
}

func (c *serverClient) handleStream(stream quic.Stream) {
	// Read request
	var req clientRequest
	err := struc.Unpack(stream, &req)
	if err != nil {
		return
	}
	if !req.UDP {
		// TCP connection
		c.handleTCP(stream, req.Host, req.Port)
	} else if !c.DisableUDP {
		// UDP connection
		c.handleUDP(stream)
	} else {
		// UDP disabled
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "UDP disabled",
		})
	}
}

func (c *serverClient) handleMessage(msg []byte) {
	var udpMsg udpMessage
	err := struc.Unpack(bytes.NewBuffer(msg), &udpMsg)
	if err != nil {
		return
	}
	dfMsg := c.udpDefragger.Feed(udpMsg)
	if dfMsg == nil {
		return
	}
	c.udpSessionMutex.RLock()
	conn, ok := c.udpSessionMap[dfMsg.SessionID]
	c.udpSessionMutex.RUnlock()
	if ok {
		// Session found, send the message
		action, arg := acl.ActionDirect, ""
		var isDomain bool
		var ipAddr *net.IPAddr
		var err error
		if c.ACLEngine != nil {
			action, arg, isDomain, ipAddr, err = c.ACLEngine.ResolveAndMatch(dfMsg.Host, dfMsg.Port, true)
		} else if c.Transport.ProxyEnabled() { // Case for SOCKS5 outbound
			ipAddr, isDomain = c.Transport.ParseIPAddr(dfMsg.Host) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
			err = nil
		} else {
			ipAddr, isDomain, err = c.Transport.ResolveIPAddr(dfMsg.Host)
		}
		if err != nil {
			return
		}
		switch action {
		case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
			addrEx := &transport.AddrEx{
				IPAddr: ipAddr,
				Port:   int(dfMsg.Port),
			}
			if isDomain {
				addrEx.Domain = dfMsg.Host
			}
			_, _ = conn.WriteTo(dfMsg.Data, addrEx)
			if c.TrafficCounter != nil {
				c.TrafficCounter.Tx(c.AuthLabel, len(dfMsg.Data))
			}
		case acl.ActionBlock:
			// Do nothing
		case acl.ActionHijack:
			var isDomain bool
			var hijackIPAddr *net.IPAddr
			var err error
			if c.Transport.ProxyEnabled() { // Case for domain requests + SOCKS5 outbound
				hijackIPAddr, isDomain = c.Transport.ParseIPAddr(arg) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
				err = nil
			} else {
				hijackIPAddr, isDomain, err = c.Transport.ResolveIPAddr(arg)
			}
			if err == nil {
				addrEx := &transport.AddrEx{
					IPAddr: hijackIPAddr,
					Port:   int(dfMsg.Port),
				}
				if isDomain {
					addrEx.Domain = arg
				}
				_, _ = conn.WriteTo(dfMsg.Data, addrEx)
				if c.TrafficCounter != nil {
					c.TrafficCounter.Tx(c.AuthLabel, len(dfMsg.Data))
				}
			}
		default:
			// Do nothing
		}
	}
}

func (c *serverClient) handleTCP(stream quic.Stream, host string, port uint16) {
	addrStr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	action, arg := acl.ActionDirect, ""
	var isDomain bool
	var ipAddr *net.IPAddr
	var err error
	if c.ACLEngine != nil {
		action, arg, isDomain, ipAddr, err = c.ACLEngine.ResolveAndMatch(host, port, false)
	} else if c.Transport.ProxyEnabled() { // Case for domain requests + SOCKS5 outbound
		ipAddr, isDomain = c.Transport.ParseIPAddr(host) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
		err = nil
	} else {
		ipAddr, isDomain, err = c.Transport.ResolveIPAddr(host)
	}
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "host resolution failure",
		})
		c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
		return
	}
	c.CTCPRequestFunc(c.ClientAddr(), c.Auth, addrStr, action, arg)

	var conn net.Conn // Connection to be piped
	switch action {
	case acl.ActionDirect, acl.ActionProxy: // Treat proxy as direct on server side
		addrEx := &transport.AddrEx{
			IPAddr: ipAddr,
			Port:   int(port),
		}
		if isDomain {
			addrEx.Domain = host
		}
		conn, err = c.Transport.DialTCP(addrEx)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
			return
		}
	case acl.ActionBlock:
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "blocked by ACL",
		})
		return
	case acl.ActionHijack:
		var isDomain bool
		var hijackIPAddr *net.IPAddr
		var err error
		if c.Transport.ProxyEnabled() { // Case for domain requests + SOCKS5 outbound
			hijackIPAddr, isDomain = c.Transport.ParseIPAddr(arg) // It is safe to leave ipAddr as nil since addrExToSOCKS5Addr will ignore it when there is a domain
			err = nil
		} else {
			hijackIPAddr, isDomain, err = c.Transport.ResolveIPAddr(arg)
		}
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
			return
		}
		addrEx := &transport.AddrEx{
			IPAddr: hijackIPAddr,
			Port:   int(port),
		}
		if isDomain {
			addrEx.Domain = arg
		}
		conn, err = c.Transport.DialTCP(addrEx)
		if err != nil {
			_ = struc.Pack(stream, &serverResponse{
				OK:      false,
				Message: err.Error(),
			})
			c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
			return
		}
	default:
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "ACL error",
		})
		return
	}
	// So far so good if we reach here
	defer conn.Close()
	err = struc.Pack(stream, &serverResponse{
		OK: true,
	})
	if err != nil {
		return
	}
	// Sniff host only when the client sent a bare IP, and only for HTTP/TLS.
	// Hysteria 1's client waits for serverResponse before sending payload,
	// so sniffing must happen after OK was sent.
	if c.ACLEngine != nil && net.ParseIP(host) != nil && (port == 443 || port == 80) {
		const sniffTimeout = 700 * time.Millisecond
		const maxSniffBytes = 32768
		buf := make([]byte, maxSniffBytes)
		total := 0
		_ = stream.SetReadDeadline(time.Now().Add(sniffTimeout))
		for total < len(buf) {
			n, readErr := stream.Read(buf[total:])
			total += n
			domain, done := sniffTCPHostname(buf[:total])
			if domain != "" {
				// Apply the existing ACL's decision using the sniffed hostname.
				// Destination remains the original IP: no DNS-based rerouting.
				sniffAction, _, _, _, matchErr := c.ACLEngine.ResolveAndMatch(domain, port, false)
				if matchErr == nil && sniffAction == acl.ActionBlock {
					_ = stream.SetReadDeadline(time.Time{})
					return
				}
			}
			if done || readErr != nil || n == 0 {
				break
			}
		}
		_ = stream.SetReadDeadline(time.Time{})
		if total > 0 {
			written, writeErr := io.Copy(conn, bytes.NewReader(buf[:total]))
			if writeErr != nil {
				return
			}
			if c.TrafficCounter != nil {
				c.TrafficCounter.Tx(c.AuthLabel, int(written))
			}
		}
	}
	if c.TrafficCounter != nil {
		err = utils.Pipe2Way(stream, conn, func(i int) {
			if i > 0 {
				c.TrafficCounter.Tx(c.AuthLabel, i)
			} else {
				c.TrafficCounter.Rx(c.AuthLabel, -i)
			}
		})
	} else {
		err = utils.Pipe2Way(stream, conn, nil)
	}
	c.CTCPErrorFunc(c.ClientAddr(), c.Auth, addrStr, err)
}

func (c *serverClient) handleUDP(stream quic.Stream) {
	// Like in SOCKS5, the stream here is only used to maintain the UDP session. No need to read anything from it
	conn, err := c.Transport.ListenUDP()
	if err != nil {
		_ = struc.Pack(stream, &serverResponse{
			OK:      false,
			Message: "UDP initialization failed",
		})
		c.CUDPErrorFunc(c.ClientAddr(), c.Auth, 0, err)
		return
	}
	defer conn.Close()

	var id uint32
	c.udpSessionMutex.Lock()
	id = c.nextUDPSessionID
	c.udpSessionMap[id] = conn
	c.nextUDPSessionID += 1
	c.udpSessionMutex.Unlock()

	err = struc.Pack(stream, &serverResponse{
		OK:           true,
		UDPSessionID: id,
	})
	if err != nil {
		return
	}
	c.CUDPRequestFunc(c.ClientAddr(), c.Auth, id)

	// Receive UDP packets, send them to the client
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			n, rAddr, err := conn.ReadFrom(buf)
			if n > 0 {
				var msgBuf bytes.Buffer
				msg := udpMessage{
					SessionID: id,
					Host:      rAddr.IP.String(),
					Port:      uint16(rAddr.Port),
					FragCount: 1,
					Data:      buf[:n],
				}
				// try no frag first
				_ = struc.Pack(&msgBuf, &msg)
				sendErr := c.CC.SendMessage(msgBuf.Bytes())
				if sendErr != nil {
					if errSize, ok := sendErr.(quic.ErrMessageTooLarge); ok {
						// need to frag
						msg.MsgID = uint16(rand.Intn(0xFFFF)) + 1 // msgID must be > 0 when fragCount > 1
						fragMsgs := fragUDPMessage(msg, int(errSize))
						for _, fragMsg := range fragMsgs {
							msgBuf.Reset()
							_ = struc.Pack(&msgBuf, &fragMsg)
							_ = c.CC.SendMessage(msgBuf.Bytes())
						}
					}
				}
				if c.TrafficCounter != nil {
					c.TrafficCounter.Rx(c.AuthLabel, n)
				}
			}
			if err != nil {
				break
			}
		}
		_ = stream.Close()
	}()

	// Hold the stream until it's closed by the client
	buf := make([]byte, 1024)
	for {
		_, err = stream.Read(buf)
		if err != nil {
			break
		}
	}
	c.CUDPErrorFunc(c.ClientAddr(), c.Auth, id, err)

	// Remove the session
	c.udpSessionMutex.Lock()
	delete(c.udpSessionMap, id)
	c.udpSessionMutex.Unlock()
}

// sniffTCPHostname returns (hostname, done). It never alters traffic.
// TLS ClientHello with ECH only exposes the outer SNI (if any).
func sniffTCPHostname(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}
	if data[0] == 0x16 {
		if len(data) < 5 {
			return "", false
		}
		if data[1] != 3 {
			return "", true
		}
		recordLen := int(binary.BigEndian.Uint16(data[3:5]))
		if recordLen < 4 || recordLen > 16384 {
			return "", true
		}
		if len(data) < 5+recordLen {
			return "", false
		}
		return sniffTLSName(data[5 : 5+recordLen]), true
	}
	if bytes.IndexByte(data, '\n') < 0 && len(data) < 16 {
		return "", false
	}
	// HTTP request: only inspect up to the first complete header block.
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return "", len(data) >= 8192
	}
	for _, line := range bytes.Split(data[:end], []byte("\r\n"))[1:] {
		if len(line) >= 5 && bytes.EqualFold(line[:5], []byte("Host:")) {
			host := strings.TrimSpace(string(line[5:]))
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			} else if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host, "]") {
				host = host[:i]
			}
			return normalizeSniffName(host), true
		}
	}
	return "", true
}

func sniffTLSName(data []byte) string {
	// TLS handshake: type(1) length(3) legacy_version(2) random(32).
	if len(data) < 4 || data[0] != 1 {
		return ""
	}
	helloLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if helloLen < 34 || helloLen+4 > len(data) {
		return ""
	}
	p := data[4 : helloLen+4]
	p = p[34:]
	if len(p) < 1 {
		return ""
	}
	n := int(p[0])
	p = p[1:]
	if len(p) < n+2 {
		return ""
	}
	p = p[n:]
	n = int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < n+1 {
		return ""
	}
	p = p[n:]
	n = int(p[0])
	p = p[1:]
	if len(p) < n+2 {
		return ""
	}
	p = p[n:]
	n = int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < n {
		return ""
	}
	p = p[:n]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p[:2])
		size := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if size > len(p) {
			return ""
		}
		if typ == 0 {
			e := p[:size]
			if len(e) < 2 {
				return ""
			}
			listLen := int(binary.BigEndian.Uint16(e[:2]))
			e = e[2:]
			if len(e) < listLen {
				return ""
			}
			e = e[:listLen]
			for len(e) >= 3 {
				kind := e[0]
				nameLen := int(binary.BigEndian.Uint16(e[1:3]))
				e = e[3:]
				if nameLen > len(e) {
					return ""
				}
				if kind == 0 {
					return normalizeSniffName(string(e[:nameLen]))
				}
				e = e[nameLen:]
			}
			return ""
		}
		p = p[size:]
	}
	return ""
}

func normalizeSniffName(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil || strings.ContainsAny(host, " \r\n\t\x00/\\") {
		return ""
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return ""
		}
	}
	return host
}
