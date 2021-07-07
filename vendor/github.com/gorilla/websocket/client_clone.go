// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.8

package websocket

import (
	"github.com/whiskerman/gmsm/gmtls"
	//"crypto/tls"
)

func cloneTLSConfig(cfg *gmtls.Config) *gmtls.Config {
	if cfg == nil {
		return &gmtls.Config{}
	}
	return cfg.Clone()
}
