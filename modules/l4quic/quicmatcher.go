// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package l4quic

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"time"

	_ "unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/quic-go/quic-go"
)

func init() {
	caddy.RegisterModule(MatchQUIC{})
}

// MatchQUIC is able to match QUIC connections. The auto-generated
// documentation for this type is wrong; instead of an object, it
// is [an array of matcher set objects](https://caddyserver.com/docs/json/apps/http/servers/routes/match/).
type MatchQUIC struct {
	SNIs           []string `json:"sni,omitempty"`
	pktConn        *net.UDPConn
	quicListener   *quic.EarlyListener
	buf            [1500]byte
	selfsignedCert *x509.Certificate
}

// CaddyModule returns the Caddy module information.
func (MatchQUIC) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.matchers.quic",
		New: func() caddy.Module { return new(MatchQUIC) },
	}
}

// Provision sets up the handler.
func (m *MatchQUIC) Provision(ctx caddy.Context) error {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	m.pktConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	_, priv, err := GenerateKey()
	if err != nil {
		return err
	}
	cert, err := GenerateCert(priv)
	if err != nil {
		return err
	}
	m.selfsignedCert = cert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv}},
	}
	m.quicListener, err = quic.ListenEarly(m.pktConn, tlsConfig, &quic.Config{})
	if err != nil {
		return err
	}
	return nil
}

// Match returns true if the conn starts with an QUIC conn.
func (m MatchQUIC) Match(cx *layer4.Connection) (bool, error) {
	if cx.Conn.LocalAddr().Network() == "udp" {
		n, err := cx.Read(m.buf[:])
		if err != nil {
			return false, err
		}

		hasQUICBit := n > 0 && m.buf[0]&0x40 != 0

		if !hasQUICBit {
			// not a quic packet
			return false, nil
		}

		n, err = m.pktConn.WriteToUDP(m.buf[:n], m.pktConn.LocalAddr().(*net.UDPAddr))
		// _, err = m.pktConn.Write(m.buf[:n])
		if err != nil {
			return false, err
		}
		earlyConn, err := m.quicListener.Accept(cx.Context)
		if err != nil {
			return false, err
		}

		// checks if the sni matches the SNIs from the config
		match := slices.Contains(m.SNIs, earlyConn.ConnectionState().TLS.ServerName)

		// add context to the conn using a replacer
		repl := cx.Context.Value(layer4.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set("l4.quic.sni", earlyConn.ConnectionState().TLS.ServerName)
		// we may have a valid QUIC conn request
		return match, nil
	}
	return false, nil
}

// The two functions below are only used for using quic-go to extract the SNI from QUIC packets.
// TODO: It would be nice to just parse the packet without using the full QUIC & TLS stack

func GenerateKey() (crypto.PublicKey, crypto.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func GenerateCert(priv crypto.PrivateKey) (*x509.Certificate, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{""},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 20),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"*"},
		IsCA:                  true,
	}

	return &cert, nil
}

// Interface guards
var (
	_ layer4.ConnMatcher = (*MatchQUIC)(nil)
	_ caddy.Provisioner  = (*MatchQUIC)(nil)
)
