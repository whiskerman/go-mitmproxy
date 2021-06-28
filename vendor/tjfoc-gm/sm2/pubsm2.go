package sm2

import (
	"io"
	"math/big"
)

func Sign(rand io.Reader, priv *PrivateKey, msg []byte) (r, s *big.Int, err error) {
	r, s, err = Sm2Sign(priv, msg, nil, rand)
	if err != nil {
		return
	}
	return
}

func Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	return Sm2Verify(pub, msg, default_uid, r, s)
}
