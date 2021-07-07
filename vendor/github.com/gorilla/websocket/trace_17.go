// +build !go1.8

package websocket

import (
	
	"github.com/whiskerman/gmsm/gmtls"
	//"crypto/tls"
	"net/http/httptrace"
)

func doHandshakeWithTrace(trace *httptrace.ClientTrace, tlsConn *gmtls.Conn, cfg *gmtls.Config) error {
	return doHandshake(tlsConn, cfg)
}
