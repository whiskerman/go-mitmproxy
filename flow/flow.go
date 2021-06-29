package flow

import (
	"net/url"

	"github.com/whiskerman/go-mitmproxy/net/http"

	_log "github.com/sirupsen/logrus"
)

var log = _log.WithField("at", "flow")

type Request struct {
	Method string
	URL    *url.URL
	Proto  string
	Header http.Header
	Body   []byte

	raw *http.Request
}

func NewRequest(req *http.Request) *Request {
	return &Request{
		Method: req.Method,
		URL:    req.URL,
		Proto:  req.Proto,
		Header: req.Header,
		raw:    req,
	}
}

func (r *Request) Raw() *http.Request {
	return r.raw
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte

	decodedBody []byte
	decoded     bool // decoded reports whether the response was sent compressed but was decoded to decodedBody.
	decodedErr  error
}

type Flow struct {
	*Request
	*Response

	// https://docs.mitmproxy.org/stable/overview-features/#streaming
	// 如果为 true，则不缓冲 Request.Body 和 Response.Body，且不进入之后的 Addon.Request 和 Addon.Response
	Stream bool
	done   chan struct{}
}

func NewFlow() *Flow {
	return &Flow{done: make(chan struct{})}
}

func (f *Flow) Done() <-chan struct{} {
	return f.done
}

func (f *Flow) Finish() {
	close(f.done)
}
