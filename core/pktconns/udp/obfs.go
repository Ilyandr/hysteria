package udp

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/apernet/hysteria/core/pktconns/obfs"
	"golang.org/x/net/ipv4"
)

const udpBufferSize = 4096

type ObfsUDPPacketConn struct {
	orig *net.UDPConn
	obfs obfs.Obfuscator

	readBuf    []byte
	readMutex  sync.Mutex
	writeBuf   []byte
	writeMutex sync.Mutex
}

func NewObfsUDPConn(orig *net.UDPConn, ob obfs.Obfuscator) *ObfsUDPPacketConn {
	return &ObfsUDPPacketConn{
		orig:     orig,
		obfs:     ob,
		readBuf:  make([]byte, udpBufferSize),
		writeBuf: make([]byte, udpBufferSize),
	}
}

// ReadMsgUDP preserves IP_PKTINFO and ECN OOB data.
func (c *ObfsUDPPacketConn) ReadMsgUDP(
	p, oob []byte,
) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	for {
		rn, roobn, rflags, raddr, rerr :=
			c.orig.ReadMsgUDP(c.readBuf, oob)

		if rerr != nil {
			return 0, roobn, rflags, raddr, rerr
		}

		if rn <= 0 || rflags&syscall.MSG_TRUNC != 0 {
			continue
		}

		decoded := c.obfs.Deobfuscate(c.readBuf[:rn], p)
		if decoded <= 0 {
			continue
		}

		return decoded, roobn, rflags, raddr, nil
	}
}

// WriteMsgUDP preserves destination-specific source IP.
// OOB contains packet info produced by quic-go.
func (c *ObfsUDPPacketConn) WriteMsgUDP(
	p, oob []byte,
	addr *net.UDPAddr,
) (n, oobn int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	bn := c.obfs.Obfuscate(p, c.writeBuf)
	if bn <= 0 {
		return 0, 0, errors.New("XPlus obfuscation failed")
	}

	_, oobn, err = c.orig.WriteMsgUDP(c.writeBuf[:bn], oob, addr)
	if err != nil {
		return 0, oobn, err
	}

	return len(p), oobn, nil
}

// ReadBatch ensures the quic-go batch path also applies XPlus.
// Initial implementation processes one packet per call.
func (c *ObfsUDPPacketConn) ReadBatch(
	msgs []ipv4.Message,
	flags int,
) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	msg := &msgs[0]
	if len(msg.Buffers) == 0 {
		return 0, errors.New("ReadBatch: no destination buffer")
	}

	n, oobn, rflags, addr, err :=
		c.ReadMsgUDP(msg.Buffers[0], msg.OOB)

	if err != nil {
		return 0, err
	}

	msg.N = n
	msg.NN = oobn
	msg.Flags = rflags
	msg.Addr = addr

	return 1, nil
}

// WriteBatch ensures packets aren't sent without XPlus.
func (c *ObfsUDPPacketConn) WriteBatch(
	msgs []ipv4.Message,
	flags int,
) (int, error) {
	for i := range msgs {
		msg := &msgs[i]

		if len(msg.Buffers) != 1 {
			return i, errors.New("WriteBatch: expected one buffer")
		}

		addr, ok := msg.Addr.(*net.UDPAddr)
		if !ok {
			return i, errors.New("WriteBatch: invalid UDP address")
		}

		n, oobn, err :=
			c.WriteMsgUDP(msg.Buffers[0], msg.OOB, addr)

		if err != nil {
			return i, err
		}

		msg.N = n
		msg.NN = oobn
	}

	return len(msgs), nil
}

func (c *ObfsUDPPacketConn) ReadFrom(
	p []byte,
) (int, net.Addr, error) {
	n, _, _, addr, err := c.ReadMsgUDP(p, nil)
	return n, addr, err
}

func (c *ObfsUDPPacketConn) WriteTo(
	p []byte,
	addr net.Addr,
) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("WriteTo: invalid UDP address")
	}

	n, _, err := c.WriteMsgUDP(p, nil, udpAddr)
	return n, err
}

func (c *ObfsUDPPacketConn) Close() error {
	return c.orig.Close()
}

func (c *ObfsUDPPacketConn) LocalAddr() net.Addr {
	return c.orig.LocalAddr()
}

func (c *ObfsUDPPacketConn) SetDeadline(t time.Time) error {
	return c.orig.SetDeadline(t)
}

func (c *ObfsUDPPacketConn) SetReadDeadline(t time.Time) error {
	return c.orig.SetReadDeadline(t)
}

func (c *ObfsUDPPacketConn) SetWriteDeadline(t time.Time) error {
	return c.orig.SetWriteDeadline(t)
}

func (c *ObfsUDPPacketConn) SetReadBuffer(bytes int) error {
	return c.orig.SetReadBuffer(bytes)
}

func (c *ObfsUDPPacketConn) SetWriteBuffer(bytes int) error {
	return c.orig.SetWriteBuffer(bytes)
}

func (c *ObfsUDPPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.orig.SyscallConn()
}

func (c *ObfsUDPPacketConn) File() (*os.File, error) {
	return c.orig.File()
}