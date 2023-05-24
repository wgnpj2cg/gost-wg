package gost

import (
	"context"
	"net"

	"github.com/octeep/wireproxy"
)

type wireguardDial func(ctx context.Context, network, address string) (net.Conn, error)

func WireguardDial(configFile string) (wireguardDial, error) {
	config, err := wireproxy.ParseConfig(configFile)
	if err != nil {
		return nil, err
	}

	logLevel := 1
	if Debug {
		logLevel = 2
	}

	vt, err := wireproxy.StartWireguard(config.Device, logLevel)
	if err != nil {
		return nil, err
	}

	return vt.Tnet.DialContext, nil
}

type wireguardConnector struct {
}

func WireguardConnector() Connector {
	return &wireguardConnector{}
}

func (c *wireguardConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *wireguardConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	return conn.(*wireguardConn).Dial(ctx, network, address)
}

type wireguardTransporter struct {
	conn *wireguardConn
}

func WireguardTransporter(dial wireguardDial) Transporter {
	return &wireguardTransporter{
		conn: &wireguardConn{Dial: dial},
	}
}

func (tr *wireguardTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	return tr.conn, nil
}

func (tr *wireguardTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *wireguardTransporter) Multiplex() bool {
	return true
}

type wireguardConn struct {
	nopConn
	Dial wireguardDial
}
