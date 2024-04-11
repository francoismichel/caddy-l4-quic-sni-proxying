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

package l4udp

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

type UDPUpstream struct {
	remoteAddr *net.UDPAddr
	localAddr  *net.UDPAddr
	conn       *net.UDPConn
}

// UnmarshalJSON satisfies the json.Unmarshaler interface.
func (u *UDPUpstream) UnmarshalJSON(b []byte) error {
	var strAddr string
	err := json.Unmarshal(b, &strAddr)
	if err != nil {
		return err
	}
	u.remoteAddr, err = net.ResolveUDPAddr("udp", strAddr)
	if err != nil {
		return err
	}
	u.localAddr, err = net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		return err
	}
	u.conn, err = net.DialUDP("udp", u.localAddr, u.remoteAddr)
	if err != nil {
		return err
	}
	return nil
}

// MarshalJSON satisfies the json.Marshaler interface.
func (m *UDPUpstream) MarshalJSON() ([]byte, error) {
	return nil, nil
}

type UDPAddr struct {
	*net.UDPAddr
}

func (a *UDPAddr) UnmarshalJSON(b []byte) error {
	var strAddr string
	err := json.Unmarshal(b, &strAddr)
	if err != nil {
		return err
	}
	addr, err := net.ResolveUDPAddr("udp", strAddr)
	if err != nil {
		return err
	}
	a.UDPAddr = addr
	return nil
}

// Handler is a handler that can proxy connections.
type Handler struct {
	// Upstreams is the list of backends to proxy to.
	// Upstream UDPUpstream `json:"upstream,omitempty"`
	RemoteAddr *UDPAddr `json:"upstream,omitempty"`

	ctx caddy.Context

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.udpproxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.ctx = ctx
	h.logger = ctx.Logger(h)

	return nil
}

// Handle handles the downstream connection.
func (h Handler) Handle(down *layer4.Connection, _ layer4.Handler) error {
	if down.Conn.LocalAddr().Network() != "udp" {
		return fmt.Errorf("down connection is not a UDP connection")
	}
	localAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		return err
	}
	upstreamConn, err := net.DialUDP("udp", localAddr, h.RemoteAddr.UDPAddr)
	if err != nil {
		return err
	}
	defer upstreamConn.Close()
	go func() {
		buf := make([]byte, 9000)
		for {
			n, err := down.Read(buf)
			if err != nil {
				h.logger.Error(fmt.Sprintf("error when reading UDP down connection: %s", err))
				return
			}
			n, err = upstreamConn.Write(buf[:n])
			if err != nil {
				h.logger.Error(fmt.Sprintf("error when writing UDP upstream connection: %s", err))
				return
			}
		}
	}()

	buf := make([]byte, 9000)
	for {
		n, err := upstreamConn.Read(buf)
		if err != nil {
			h.logger.Error(fmt.Sprintf("error when reading UDP upstream connection: %s", err))
			return err
		}
		n, err = down.Write(buf[:n])
		if err != nil {
			h.logger.Error(fmt.Sprintf("error when writing UDP downstream connection: %s", err))
			return err
		}
	}
}

// Interface guards
var (
	_ json.Marshaler   = (*UDPUpstream)(nil)
	_ json.Unmarshaler = (*UDPUpstream)(nil)
)
