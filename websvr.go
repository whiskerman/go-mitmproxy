package websvr

import (
	"io/ioutil"

	tls "github.com/whiskerman/gmsm/gmtls"
	"github.com/whiskerman/gmsm/x509"

	x "github.com/whiskerman/gmsm/x509"
)

const (
	rsaCertPath     = "./certs/rsa_sign.cer"
	rsaKeyPath      = "./certs/rsa_sign_key.pem"
	RSACaCertPath   = "./certs/RSA_CA.cer"
	RSAAuthCertPath = "./certs/rsa_auth_cert.cer"
	RSAAuthKeyPath  = "./certs/rsa_auth_key.pem"
	SM2CaCertPath   = "./certs/SM2_CA.cer"
	SM2AuthCertPath = "./certs/sm2_auth_cert.cer"
	SM2AuthKeyPath  = "./certs/sm2_auth_key.pem"
	sm2SignCertPath = "./certs/sm2_sign_cert.cer"
	sm2SignKeyPath  = "./certs/sm2_sign_key.pem"
	sm2EncCertPath  = "./certs/sm2_enc_cert.cer"
	sm2EncKeyPath   = "./certs/sm2_enc_key.pem"
)

// RSA配置
func loadRsaConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// SM2配置
func loadSM2Config() (*tls.Config, error) {
	sigCert, err := tls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := tls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		GMSupport:    &tls.GMSupport{},
		Certificates: []tls.Certificate{sigCert, encCert},
	}, nil
}

// 切换GMSSL/TSL
func loadAutoSwitchConfig() (*tls.Config, error) {
	rsaKeypair, err := tls.LoadX509KeyPair(rsaCertPath, rsaKeyPath)
	if err != nil {
		return nil, err
	}
	sigCert, err := tls.LoadX509KeyPair(sm2SignCertPath, sm2SignKeyPath)
	if err != nil {
		return nil, err
	}
	encCert, err := tls.LoadX509KeyPair(sm2EncCertPath, sm2EncKeyPath)
	if err != nil {
		return nil, err

	}
	return tls.NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaKeypair)
}

// 要求客户端身份认证
func loadAutoSwitchConfigClientAuth() (*tls.Config, error) {
	config, err := loadAutoSwitchConfig()
	if err != nil {
		return nil, err
	}
	// 设置需要客户端证书请求，标识需要进行客户端的身份认证
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return config, nil
}

// 获取 客户端服务端双向身份认证 配置
func bothAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(SM2AuthCertPath, SM2AuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		GMSupport:          &tls.GMSupport{},
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func singleSideAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(SM2CaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		GMSupport: &tls.GMSupport{},
		RootCAs:   certPool,
	}, nil
}

// 获取 客户端服务端双向身份认证 配置
func rsaBothAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)
	authKeypair, err := tls.LoadX509KeyPair(RSAAuthCertPath, RSAAuthKeyPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MaxVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{authKeypair},
		InsecureSkipVerify: false,
	}, nil

}

// 获取 单向身份认证（只认证服务端） 配置
func rsaSingleSideAuthConfig() (*tls.Config, error) {
	// 信任的根证书
	certPool := x.NewCertPool()
	cacert, err := ioutil.ReadFile(RSACaCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(cacert)

	return &tls.Config{
		MaxVersion: tls.VersionTLS12,
		RootCAs:    certPool,
	}, nil
}
