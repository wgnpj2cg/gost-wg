package gost

import (
	"context"
	"net"

	"github.com/octeep/wireproxy"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func WireguardTunNet(configFile string) (*netstack.Net, error) {
	config, err := wireproxy.ParseConfig(configFile)
	if err != nil {
		return nil, err
	}

	tnet, err := wireproxy.StartWireguard(config.Device)
	if err != nil {
		return nil, err
	}

	return tnet.Tnet, nil
}

type wireguardConnector struct {
	tnet *netstack.Net
}

func WireguardConnector(tnet *netstack.Net) Connector {
	return &wireguardConnector{
		tnet: tnet,
	}
}

func (c *wireguardConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *wireguardConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	return c.tnet.DialContext(ctx, network, address)
}

type wireguardTransporter struct {
}

func WireguardTransporter() Transporter {
	return &wireguardTransporter{}
}

func (tr *wireguardTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	return nopClientConn, nil
}

func (tr *wireguardTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *wireguardTransporter) Multiplex() bool {
	return true
}
