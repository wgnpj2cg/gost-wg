package gost

import (
	"crypto/tls"
	"net"
	"sync"

	"github.com/golang/groupcache/lru"
	"github.com/lunixbochs/struc"
)

type MITM struct {
	Decrypt, Encrypt bool
	GetCertificate   func(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

type mitmHelloRequest struct {
	NeedProto            bool
	SupportH1, SupportH2 bool
}

type mitmHelloResponse struct {
	UseH2 bool
}

type mitmHTTP2CacheKey struct {
	ServerName           string
	SupportH1, SupportH2 bool
}

var mitmHTTP2Cache = lru.New(1024 * 1024)
var mitmHTTP2CacheMu sync.Mutex

func (m *MITM) Handshake(conn, cc net.Conn, serverName string) (net.Conn, net.Conn, error) {
	if m.Decrypt {
		return m.decrypt(conn, cc, serverName)
	} else if m.Encrypt {
		return m.encrypt(conn, cc, serverName)
	} else {
		return conn, cc, nil
	}
}

func (m *MITM) decrypt(conn, cc net.Conn, serverName string) (net.Conn, net.Conn, error) {
	tconn := tls.Server(conn, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			key := mitmHTTP2CacheKey{ServerName: serverName}
			key.SupportH1, key.SupportH2 = mitmString2Bool(chi.SupportedProtos)

			mitmHTTP2CacheMu.Lock()
			useH2, ok := mitmHTTP2Cache.Get(key)
			mitmHTTP2CacheMu.Unlock()

			if m.Encrypt {
				cc = tls.Client(cc, &tls.Config{
					ServerName: serverName,
					NextProtos: chi.SupportedProtos,
				})
			} else {
				if err := struc.Pack(cc, &mitmHelloRequest{
					NeedProto: !ok,
					SupportH1: key.SupportH1,
					SupportH2: key.SupportH2,
				}); err != nil {
					return nil, err
				}
			}

			if !ok {
				if m.Encrypt {
					tcc := cc.(*tls.Conn)
					if err := tcc.Handshake(); err != nil {
						return nil, err
					}
					useH2 = tcc.ConnectionState().NegotiatedProtocol == "h2"
				} else {
					var response mitmHelloResponse
					if err := struc.Unpack(cc, &response); err != nil {
						return nil, err
					}
					useH2 = response.UseH2
				}

				mitmHTTP2CacheMu.Lock()
				mitmHTTP2Cache.Add(key, useH2)
				mitmHTTP2CacheMu.Unlock()
			}

			return &tls.Config{
				GetCertificate: m.GetCertificate,
				NextProtos:     mitmBool2String(!useH2.(bool), useH2.(bool)),
			}, nil
		},
	})

	if err := tconn.Handshake(); err != nil {
		return nil, nil, err
	}

	return tconn, cc, nil
}

func (m *MITM) encrypt(conn, cc net.Conn, serverName string) (net.Conn, net.Conn, error) {
	var request mitmHelloRequest
	if err := struc.Unpack(conn, &request); err != nil {
		return nil, nil, err
	}

	tcc := tls.Client(cc, &tls.Config{
		ServerName: serverName,
		NextProtos: mitmBool2String(request.SupportH1, request.SupportH2),
	})

	if request.NeedProto {
		if err := tcc.Handshake(); err != nil {
			return nil, nil, err
		}
		if err := struc.Pack(conn, &mitmHelloResponse{
			UseH2: tcc.ConnectionState().NegotiatedProtocol == "h2",
		}); err != nil {
			return nil, nil, err
		}
	}

	return conn, tcc, nil
}

func mitmString2Bool(protos []string) (supportH1, supportH2 bool) {
	for _, proto := range protos {
		if proto == "http/1.1" {
			supportH1 = true
		}
		if proto == "h2" {
			supportH2 = true
		}
	}
	return
}

func mitmBool2String(supportH1, supportH2 bool) (protos []string) {
	if supportH2 {
		protos = append(protos, "h2")
	}
	if supportH1 {
		protos = append(protos, "http/1.1")
	}
	return
}
