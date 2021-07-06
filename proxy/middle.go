package proxy

import (
	"bufio"
	"net"
	"strings"

	"net/http"

	"github.com/whiskerman/go-mitmproxy/fosafercert"
)

// 模拟了标准库中 server 运行，目的是仅通过当前进程内存转发 socket 数据，不需要经过 tcp 或 unix socket

// mock net.Listener
type listener struct {
	connChan chan net.Conn
}

func (l *listener) Accept() (net.Conn, error) { return <-l.connChan, nil }
func (l *listener) Close() error              { return nil }
func (l *listener) Addr() net.Addr            { return nil }

// 建立客户端和服务端通信的通道
func newPipes(host string) (net.Conn, *connBuf) {
	client, srv := net.Pipe()
	server := newConnBuf(srv, host)
	return client, server
}

// add Peek method for conn
type connBuf struct {
	net.Conn
	r    *bufio.Reader
	host string
}

func newConnBuf(c net.Conn, host string) *connBuf {
	return &connBuf{
		Conn: c,
		r:    bufio.NewReader(c),
		host: host,
	}
}

func (b *connBuf) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b *connBuf) Read(data []byte) (int, error) {
	return b.r.Read(data)
}

// Middle: man-in-the-middle
type Middle struct {
	Proxy    *Proxy
	CA       *fosafercert.CA
	Listener net.Listener
	Server   *http.Server
}

func NewMiddle(proxy *Proxy) (Interceptor, error) {
	ca, err := fosafercert.NewCA("")
	if err != nil {
		return nil, err
	}

	m := &Middle{
		Proxy: proxy,
		CA:    ca,
	}
	/*
		fncGetSignCertKeypair := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			gmFlag := false
			// 检查支持协议中是否包含GMSSL
			for _, v := range info.SupportedVersions {
				if v == tls.VersionGMSSL {
					log.Printf("ssl version:%v", v)
					gmFlag = true
					break
				}
			}

			if gmFlag {
				log.Printf("gmssl sign info:%v", info)
				return ca.GetSM2SignCert(info.ServerName)
			} else {
				log.Printf("rsa ssl info:%v", info)
				return ca.GetRSACert(info.ServerName)
			}
		}

		fncGetEncCertKeypair := func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			log.Printf("gm ssl enc info:%v", info)
			return ca.GetSM2EncCert(info.ServerName)
		}
		support := &tls.GMSupport{WorkMode: tls.ModeAutoSwitch} //NewGMSupport()
		support.EnableMixMode()
	*/
	server := &http.Server{
		Handler: m,
		//TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // disable http2
		/*TLSConfig: &tls.Config{
			GMSupport:        support,
			GetCertificate:   fncGetSignCertKeypair,
			GetKECertificate: fncGetEncCertKeypair,
		},
		*/
	}

	m.Server = server
	m.Listener = &listener{make(chan net.Conn)}

	return m, nil
}

func (m *Middle) Start() error {
	return m.Server.ServeTLS(m.Listener, "", "")
}

func (m *Middle) Dial(host string) (net.Conn, error) {
	clientConn, serverConn := newPipes(host)
	go m.intercept(serverConn)
	return clientConn, nil
}

func (m *Middle) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		// wss
		DefaultWebSocket.WSS(res, req)
		return
	}

	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	m.Proxy.ServeHTTP(res, req)
}

// 解析 connect 流量
// 如果是 tls 流量，则进入 listener.Accept => Middle.ServeHTTP
// 否则很可能是 ws 流量
func (m *Middle) intercept(serverConn *connBuf) {
	log := log.WithField("in", "Middle.intercept").WithField("host", serverConn.host)

	buf, err := serverConn.Peek(3)
	if err != nil {
		log.Errorf("Peek error: %v\n", err)
		serverConn.Close()
		return
	}
	log.Printf("buf[0]:%x buf[1]:%x buf[2]:%x", buf[0], buf[1], buf[2])
	if buf[0] == 0x16 && buf[1] == 0x03 && (buf[2] >= 0x0 || buf[2] <= 0x03) {
		// tls
		m.Listener.(*listener).connChan <- serverConn
	} else if buf[0] == 0x16 && buf[1] == 0x01 && (buf[2] >= 0x0 || buf[2] <= 0x03) {
		// tls
		m.Listener.(*listener).connChan <- serverConn
	} else {
		// ws
		DefaultWebSocket.WS(serverConn, serverConn.host)
	}
}
