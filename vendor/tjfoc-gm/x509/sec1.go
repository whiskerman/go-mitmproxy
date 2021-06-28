package x509

import "gitee.com/china_uni/tjfoc-gm/sm2"

// MarshalECPrivateKey marshals an EC private key into ASN.1, DER format.
func MarshalECPrivateKey(key interface{}) ([]byte, error) {
	return MarshalSm2PrivateKey(key.(*sm2.PrivateKey), nil)
}
