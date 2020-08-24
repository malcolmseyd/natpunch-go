package crypto

import (
	"encoding/base64"
	"strconv"
)

// NewSession creates a new Session object and returns a pointer
// func NewSession(priv []byte, theirPub []byte) (*Session, error) {
// 	if len(priv) != 32 || len(theirPub) != 32 {
// 		return nil, ErrKeysize
// 	}

// 	var err error
// 	s := Session{
// 		staticPriv:     priv,
// 		theirStaticPub: theirPub,
// 	}

// 	ephem, err := genKeyPair()
// 	if err != nil {
// 		return nil, err
// 	}
// 	s.ephemPriv = ephem.priv
// 	s.ephemPub = ephem.pub

// 	// do the work only once
// 	s.staticPub, err = genPubkey(priv)
// 	if err != nil {
// 		return nil, err
// 	}
// 	s.sendCounter = 0
// 	//  non-zero for testing, shouldn't be a problem practically
// 	for s.sendIndex == 0 {
// 		err = binary.Read(rand.Reader, binary.BigEndian, &s.sendIndex)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}
// 	return &s, nil
// }

// String is for debugging purposes.
func (s *Session) String() string {
	str := "== session ==\n"
	str += "static privkey: " + base64.StdEncoding.EncodeToString(s.staticPriv) + "\n"
	str += "static pubkey:  " + base64.StdEncoding.EncodeToString(s.staticPub) + "\n"
	str += "\n"
	str += "ephemeral privkey: " + base64.StdEncoding.EncodeToString(s.ephemPriv) + "\n"
	str += "ephemeral pubkey:  " + base64.StdEncoding.EncodeToString(s.ephemPub) + "\n"
	str += "\n"
	str += "index:   " + strconv.FormatUint(uint64(s.sendIndex), 10) + "\n"
	str += "counter: " + strconv.FormatUint(uint64(s.sendIndex), 10) + "\n"
	return str
}

// CountSend increments the send counter. This should be called when a packet is successfully sent.
// There's no CountRecv because the packet needs to be verified upon decryption before we increment that.
func (s *Session) CountSend() {
	s.sendCounter++
}
