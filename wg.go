package gost

import (
	"context"
	"log"
	"net"

	"github.com/octeep/wireproxy"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wireguardConnector struct {
	Tnet *netstack.Net
}

func WireguardConnector(conf_path string) Connector {
	conf, err := wireproxy.ParseConfig(conf_path)
	if err != nil {
		log.Fatal(err)
	}

	tnet, err := wireproxy.StartWireguard(conf.Device)
	if err != nil {
		log.Fatal(err)
	}

	return &wireguardConnector{
		Tnet: tnet.Tnet,
	}
}

func (c *wireguardConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *wireguardConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	return c.Tnet.DialContext(ctx, network, address)
}

type wireguardTransporter struct {
}

func WireguardTransporter() Transporter {
	return &wireguardTransporter{}
}

func (tr *wireguardTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	return &fakeTCPConn{}, nil
}

func (tr *wireguardTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *wireguardTransporter) Multiplex() bool {
	return true
}

func (c *fakeTCPConn) Close() error {
	return nil
}
