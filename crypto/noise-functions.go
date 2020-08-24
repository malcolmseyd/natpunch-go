package crypto

import (
	"crypto/rand"
)

// thank you to wireguard-go for this
// we need to do this to guarantee that the key is secure
// read here: https://web.archive.org/web/20200824034945/https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/
func (n *noiseKey) clamp() {
	n[0] &= 248
	n[31] = (n[31] & 127) | 64
}

func (n *noiseKey) isEmpty() bool {
	for i := range n {
		if n[i] != 0 {
			return true
		}
	}
	return false
}

func (k *keyPair) generate() (err error) {
	rand.Read(k.priv[:])
	k.priv.clamp()
	k.pub, err = genPubkey(k.priv)
	if err != nil {
		return err
	}
	return nil
}
