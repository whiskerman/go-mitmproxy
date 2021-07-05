package fosafercert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	stls "crypto/tls"
	sx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/golang/groupcache/singleflight"
	_log "github.com/sirupsen/logrus"
	"github.com/whiskerman/gmsm/sm2"
	x509 "github.com/whiskerman/gmsm/x509"
)

var log = _log.WithField("at", "fosafercert")

// reference
// https://docs.mitmproxy.org/stable/concepts-certificates/
// https://github.com/mitmproxy/mitmproxy/blob/master/mitmproxy/certs.py

var rsacaErrNotFound = errors.New("fosaferRsaCa not found")
var sm2caErrNotFound = errors.New("fosaferSm2Ca not found")

type CA struct {
	sm2PrivateKey   sm2.PrivateKey
	rsaPrivateKey   rsa.PrivateKey
	RootRSACert     sx509.Certificate
	RootSM2Cert     x509.Certificate
	RootSM2SignCert x509.Certificate
	RootSM2EncCert  x509.Certificate
	RootSM2SignKey  sm2.PrivateKey
	RootSM2EncKey   sm2.PrivateKey
	StorePath       string

	cache         *lru.Cache
	group         *singleflight.Group
	smsigncache   *lru.Cache
	smsigngroup   *singleflight.Group
	smenccache    *lru.Cache
	smencgroup    *singleflight.Group
	smsigncacheMu sync.Mutex
	smenccacheMu  sync.Mutex

	cacheMu sync.Mutex
}

func NewCA(path string) (*CA, error) {
	storePath, err := getStorePath(path)
	if err != nil {
		return nil, err
	}

	ca := &CA{
		StorePath:   storePath,
		cache:       lru.New(100),
		group:       new(singleflight.Group),
		smsigncache: lru.New(100),
		smsigngroup: new(singleflight.Group),
		smenccache:  lru.New(100),
		smencgroup:  new(singleflight.Group),
	}

	if err := ca.load(); err != nil {
		if err != rsacaErrNotFound {
			return nil, err
		}
	} else {
		log.Debug("load root ca")
		return ca, nil
	}

	if err := ca.create(); err != nil {
		return nil, err
	}
	log.Debug("create root ca")

	return ca, nil
}

func getStorePath(path string) (string, error) {
	if path == "" {
		execpath, err := os.Executable()
		if err != nil {
			log.Println(err)
		}
		path = filepath.Dir(execpath)
		path = filepath.Join(path, "certs")
	}

	if !filepath.IsAbs(path) {
		dir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		path = filepath.Join(dir, path)
	}

	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(path, os.ModePerm)
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	} else {
		if !stat.Mode().IsDir() {
			return "", fmt.Errorf("路径 %v 不是文件夹，请移除此文件重试", path)
		}
	}

	return path, nil

	/*
		if path == "" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			path = filepath.Join(homeDir, ".mitmproxy")
		}

		if !filepath.IsAbs(path) {
			dir, err := os.Getwd()
			if err != nil {
				return "", err
			}
			path = filepath.Join(dir, path)
		}

		stat, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				err = os.MkdirAll(path, os.ModePerm)
				if err != nil {
					return "", err
				}
			} else {
				return "", err
			}
		} else {
			if !stat.Mode().IsDir() {
				return "", fmt.Errorf("路径 %v 不是文件夹，请移除此文件重试", path)
			}
		}

		return path, nil
	*/
}

// The certificate and the private key in PEM format.
func (ca *CA) caRSAKeyFile() string {
	return filepath.Join(ca.StorePath, "mitmproxy-ca.pem")
}

// The certificate in PEM format.
func (ca *CA) caRSACertFile() string {
	return filepath.Join(ca.StorePath, "mitmproxy-ca-cert.pem")
}

func (ca *CA) caSM2KeyFile() string {
	return filepath.Join(ca.StorePath, "cakey.pem")
}

// The certificate in PEM format.
func (ca *CA) caSM2CertFile() string {
	return filepath.Join(ca.StorePath, "cacert.pem")
}

func (ca *CA) load() error {
	caFile := ca.caRSAKeyFile()
	stat, err := os.Stat(caFile)
	if err != nil {
		if os.IsNotExist(err) {
			return rsacaErrNotFound
		}
		return err
	}

	if !stat.Mode().IsRegular() {
		return fmt.Errorf("%v 不是文件", caFile)
	}

	data, err := ioutil.ReadFile(caFile)
	if err != nil {
		return err
	}

	keyDERBlock, data := pem.Decode(data)
	if keyDERBlock == nil {
		return fmt.Errorf("%v 中不存在 PRIVATE KEY", caFile)
	}
	certDERBlock, _ := pem.Decode(data)
	if certDERBlock == nil {
		return fmt.Errorf("%v 中不存在 CERTIFICATE", caFile)
	}

	key, err := sx509.ParsePKCS8PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return err
	}
	if v, ok := key.(*rsa.PrivateKey); ok {
		ca.rsaPrivateKey = *v
	} else {
		return errors.New("found unknown rsa private key type in PKCS#8 wrapping")
	}

	x509Cert, err := sx509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return err
	}
	ca.RootRSACert = *x509Cert

	smcaFile := ca.caSM2KeyFile()
	smstat, err := os.Stat(smcaFile)
	if err != nil {
		if os.IsNotExist(err) {
			return sm2caErrNotFound
		}
		return err
	}

	if !smstat.Mode().IsRegular() {
		return fmt.Errorf("%v 不是文件", smcaFile)
	}

	smdata, err := ioutil.ReadFile(smcaFile)
	if err != nil {
		return err
	}

	smkeyDERBlock, _ := pem.Decode(smdata)
	if smkeyDERBlock == nil {
		return fmt.Errorf("%v 中不存在 PRIVATE KEY", smcaFile)
	}
	smcertFile := ca.caSM2CertFile()
	smcertstat, err := os.Stat(smcertFile)
	if err != nil {
		if os.IsNotExist(err) {
			return sm2caErrNotFound
		}
		return err
	}

	if !smcertstat.Mode().IsRegular() {
		return fmt.Errorf("%v 不是文件", smcertFile)
	}

	smcertdata, err := ioutil.ReadFile(smcertFile)
	if err != nil {
		return err
	}

	smcertDERBlock, _ := pem.Decode(smcertdata)
	if smcertDERBlock == nil {
		return fmt.Errorf("%v 中不存在 CERTIFICATE", smcertFile)
	}

	smx509Cert, err := x509.ParseCertificate(smcertDERBlock.Bytes)
	if err != nil {
		return err
	}
	ca.RootSM2Cert = *smx509Cert

	return nil
}

func (ca *CA) create() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	ca.rsaPrivateKey = *key

	template := &sx509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName:   "mitmproxy",
			Organization: []string{"mitmproxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour * 48),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 3),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    sx509.SHA256WithRSA,
		KeyUsage:              sx509.KeyUsageCertSign | sx509.KeyUsageCRLSign,
		ExtKeyUsage: []sx509.ExtKeyUsage{
			sx509.ExtKeyUsageServerAuth,
			sx509.ExtKeyUsageClientAuth,
			sx509.ExtKeyUsageEmailProtection,
			sx509.ExtKeyUsageTimeStamping,
			sx509.ExtKeyUsageCodeSigning,
			sx509.ExtKeyUsageMicrosoftCommercialCodeSigning,
			sx509.ExtKeyUsageMicrosoftServerGatedCrypto,
			sx509.ExtKeyUsageNetscapeServerGatedCrypto,
		},
	}

	certBytes, err := sx509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := sx509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}
	ca.RootRSACert = *cert

	if err := ca.save(); err != nil {
		return err
	}
	return ca.saveRSACert()
}

func (ca *CA) saveRSATo(out io.Writer) error {
	keyBytes, err := sx509.MarshalPKCS8PrivateKey(&ca.rsaPrivateKey)
	if err != nil {
		return err
	}
	err = pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return err
	}

	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: ca.RootRSACert.Raw})
}

func (ca *CA) saveRSACertTo(out io.Writer) error {
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: ca.RootRSACert.Raw})
}

func (ca *CA) save() error {
	file, err := os.Create(ca.caRSAKeyFile())
	if err != nil {
		return err
	}
	defer file.Close()

	return ca.saveRSATo(file)
}

func (ca *CA) saveRSACert() error {
	file, err := os.Create(ca.caRSACertFile())
	if err != nil {
		return err
	}
	defer file.Close()

	return ca.saveRSACertTo(file)
}

func (ca *CA) GetRSACert(commonName string) (*stls.Certificate, error) {
	ca.cacheMu.Lock()
	if val, ok := ca.cache.Get(commonName); ok {
		ca.cacheMu.Unlock()
		log.WithField("commonName", commonName).Debug("GetRSACert")
		return val.(*stls.Certificate), nil
	}
	ca.cacheMu.Unlock()

	val, err := ca.group.Do(commonName, func() (interface{}, error) {
		cert, err := ca.DummyRSACert(commonName)
		if err == nil {
			ca.cacheMu.Lock()
			ca.cache.Add(commonName, cert)
			ca.cacheMu.Unlock()
		}
		return cert, err
	})

	if err != nil {
		return nil, err
	}

	return val.(*stls.Certificate), nil
}

// TODO: 是否应该支持多个 SubjectAltName
func (ca *CA) DummyRSACert(commonName string) (*stls.Certificate, error) {
	log.WithField("commonName", commonName).Debug("DummyCert")
	template := &sx509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"mitmproxy"},
		},
		NotBefore:          time.Now().Add(-time.Hour * 48),
		NotAfter:           time.Now().Add(time.Hour * 24 * 365),
		SignatureAlgorithm: sx509.SHA256WithRSA,
		ExtKeyUsage:        []sx509.ExtKeyUsage{sx509.ExtKeyUsageServerAuth, sx509.ExtKeyUsageClientAuth},
	}

	ip := net.ParseIP(commonName)
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{commonName}
	}

	certBytes, err := sx509.CreateCertificate(rand.Reader, template, &ca.RootRSACert, &ca.rsaPrivateKey.PublicKey, &ca.rsaPrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &stls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &ca.rsaPrivateKey,
	}

	return cert, nil
}

func (ca *CA) GetSM2SignCert(commonName string) (*tls.Certificate, error) {
	ca.smsigncacheMu.Lock()
	if val, ok := ca.smsigncache.Get(commonName); ok {
		ca.smsigncacheMu.Unlock()
		log.WithField("commonName", commonName).Debug("GetSM2SignCert")
		return val.(*tls.Certificate), nil
	}
	ca.smsigncacheMu.Unlock()

	val, err := ca.smsigngroup.Do(commonName, func() (interface{}, error) {
		cert, err := ca.DummySM2SignCert(commonName)
		if err == nil {
			ca.cacheMu.Lock()
			ca.cache.Add(commonName, cert)
			ca.cacheMu.Unlock()
		}
		return cert, err
	})

	if err != nil {
		return nil, err
	}

	return val.(*stls.Certificate), nil
}

// TODO: 是否应该支持多个 SubjectAltName
func (ca *CA) DummySM2SignCert(commonName string) (*tls.Certificate, error) {
	log.WithField("commonName", commonName).Debug("DummyCert")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() / 100000),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"mitmproxy"},
		},
		NotBefore:          time.Now().Add(-time.Hour * 48),
		NotAfter:           time.Now().Add(time.Hour * 24 * 365),
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	ip := net.ParseIP(commonName)
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{commonName}
	}

	certBytes, err := x509.CreateCertificate(template, &ca.RootSM2Cert, &ca.sm2PrivateKey.PublicKey, &ca.sm2PrivateKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  &ca.sm2PrivateKey,
	}

	return cert, nil
}
