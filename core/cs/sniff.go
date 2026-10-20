package cs

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/apernet/hysteria/core/acl"
)

// sniffHostname returns a hostname from TLS ClientHello or HTTP Host.
// An empty result means that the hostname could not be determined.
func sniffHostname(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	if data[0] == 0x16 {
		return sniffTLSSNI(data)
	}

	return sniffHTTPHost(data)
}

func sniffHTTPHost(data []byte) string {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return ""
	}

	lines := bytes.Split(data[:end], []byte("\r\n"))
	for _, line := range lines[1:] {
		if len(line) < 5 || !bytes.EqualFold(line[:5], []byte("Host:")) {
			continue
		}

		host := strings.TrimSpace(string(line[5:]))
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else if i := strings.LastIndexByte(host, ':'); i >= 0 &&
			!strings.Contains(host, "]") {
			host = host[:i]
		}

		return normalizeSniffHost(host)
	}
	return ""
}

func sniffTLSSNI(data []byte) string {
	if len(data) < 9 || data[0] != 0x16 {
		return ""
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen < 4 || recordLen > 16384 ||
		len(data) < 5+recordLen {
		return ""
	}

	p := data[5 : 5+recordLen]
	if p[0] != 0x01 {
		return ""
	}

	helloLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	if helloLen+4 > len(p) {
		return ""
	}

	p = p[4 : 4+helloLen]

	if len(p) < 35 {
		return ""
	}

	// legacy_version (2), random (32)
	p = p[34:]

	sessionLen := int(p[0])
	if len(p) < 1+sessionLen+2 {
		return ""
	}
	p = p[1+sessionLen:]

	cipherLen := int(binary.BigEndian.Uint16(p[:2]))
	if len(p) < 2+cipherLen+1 {
		return ""
	}
	p = p[2+cipherLen:]

	compressionLen := int(p[0])
	if len(p) < 1+compressionLen+2 {
		return ""
	}
	p = p[1+compressionLen:]

	extensionsLen := int(binary.BigEndian.Uint16(p[:2]))
	if len(p) < 2+extensionsLen {
		return ""
	}
	p = p[2 : 2+extensionsLen]

	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]

		if extLen > len(p) {
			return ""
		}

		if extType == 0 {
			sni := p[:extLen]
			if len(sni) < 5 {
				return ""
			}

			listLen := int(binary.BigEndian.Uint16(sni[:2]))
			if listLen+2 > len(sni) {
				return ""
			}

			sni = sni[2 : 2+listLen]

			for len(sni) >= 3 {
				nameType := sni[0]
				nameLen := int(binary.BigEndian.Uint16(sni[1:3]))
				sni = sni[3:]

				if nameLen > len(sni) {
					return ""
				}

				if nameType == 0 {
					return normalizeSniffHost(string(sni[:nameLen]))
				}

				sni = sni[nameLen:]
			}
			return ""
		}

		p = p[extLen:]
	}

	return ""
}

func normalizeSniffHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || len(host) > 253 ||
		strings.ContainsAny(host, " \t\r\n\x00/\\") ||
		net.ParseIP(host) != nil {
		return ""
	}

	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
	}

	return host
}

// Checks the sniffed hostname against existing Hysteria 1 ACL rules,
// preserving their first-match order and the original destination IP.
func (c *serverClient) sniffedDomainBlocked(
	host string,
	ip net.IP,
	port uint16,
) bool {
	if c.ACLEngine == nil || host == "" {
		return false
	}

	req := acl.MatchRequest{
		Domain:   host,
		IP:       ip,
		Port:     port,
		Protocol: acl.ProtocolTCP,
		DB:       c.ACLEngine.GeoIPReader,
	}

	for _, entry := range c.ACLEngine.Entries {
		if entry.Match(req) {
			return entry.Action == acl.ActionBlock
		}
	}

	return c.ACLEngine.DefaultAction == acl.ActionBlock
}