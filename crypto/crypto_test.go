package crypto

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// Test that NewSession creates structs properly in with valid input
// Does not test errors or when it fails
func TestNewSession(t *testing.T) {
	testCases := []struct {
		desc string
		priv string
		pub  string
	}{
		{
			desc: "regular privkey 1",
			priv: "ABFDpDHFqviVx/JGmCJTXysUro17JS/60ZWpD2dm030=",
			pub:  "BbyvaVpk8P9eAXuLfetv5kaLVHmljLTMyiItYPOwCTs=",
		},
		{
			desc: "regular privkey 2",
			priv: "0CLEtP7eYTsJ6IE9j01kqCU8Z+1cxF4UwmBCyxXVkFM=",
			pub:  "xkNx31UWBNbosBFYBEvGYXbNgOqNPXGjThT79ELNBE8=",
		},
		{
			desc: "regular privkey 3",
			priv: "aGRHIy/QSD4qJ22X1opVE7fkGqbjf7HRjp9XGpYTK1o=",
			pub:  "xTBrebNi8INgVRRPLTvW04MuoAfqNMMvnf3aKUgdcWI=",
		},
		{
			desc: "zeroed privkey",
			priv: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			pub:  "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q=",
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			priv, err := base64.StdEncoding.DecodeString(tC.priv)
			if err != nil {
				t.Fatal("Bad input data:", err)
			}
			// why not
			serverPub, err := base64.StdEncoding.DecodeString(tC.priv)
			if err != nil {
				t.Fatal("Bad input data:", err)
			}

			sess, err := NewSession(priv, serverPub)
			if err != nil {
				t.Fatal(err)
			}

			if len(sess.staticPriv) != 32 || len(sess.staticPub) != 32 {

			}

			pub := base64.StdEncoding.EncodeToString(sess.staticPub)
			if pub != tC.pub {
				t.Log("Public key mismatch\n" +
					"Expected: " + tC.pub + "\n" +
					"Actual:   " + pub,
				)
				t.Fail()
			}

			if sess.sendCounter != 0 || sess.recvCounter != 0 {
				t.Log("Counters should be 0")
				t.Fail()
			}

			if sess.sendIndex == 0 {
				t.Log("Failed to set index")
				t.Fail()
			}

			if len(sess.ephemPriv) != 32 || len(sess.ephemPub) != 32 {
				t.Log("Ephemeral keys are incorrect length of", len(sess.ephemPriv), "and", len(sess.ephemPub))
				t.Fail()
			}

			ePub, err := genPubkey(sess.ephemPriv)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(ePub, sess.ephemPub) {
				t.Log("Ephemeral pubkey not generated the same both times\n" +
					"Privkey:    " + base64.StdEncoding.EncodeToString(sess.ephemPriv) + "\n" +
					"Test pub:   " + base64.StdEncoding.EncodeToString(ePub) + "\n" +
					"NewSession: " + base64.StdEncoding.EncodeToString(sess.ephemPub) + "\n",
				)
				t.Fail()
			}
		})
	}
}

func TestConstructHandshakeReq(t *testing.T) {
	priv, _ := base64.StdEncoding.DecodeString("0CLEtP7eYTsJ6IE9j01kqCU8Z+1cxF4UwmBCyxXVkFM=")
	pub, _ := base64.StdEncoding.DecodeString("xkNx31UWBNbosBFYBEvGYXbNgOqNPXGjThT79ELNBE8=")
	sess, _ := NewSession(priv, pub)

	handshake, err := sess.ConstructHandshakeReq()
	if err != nil {
		t.Fatal(err)
	}

	if len(handshake) != handshakeReqSize {
		t.Fatal("Handshake is the wrong length:", len(handshake))
	}
}

func TestParseHandshakeReq(t *testing.T) {
	peerA := struct {
		sess *Session
		pub  []byte
		priv []byte
	}{}
	peerB := struct {
		sess *Session
		pub  []byte
		priv []byte
	}{}

	peerA.priv, _ = genPrivkey()
	peerA.pub, _ = genPubkey(peerA.priv)

	peerB.priv, _ = genPrivkey()
	peerB.pub, _ = genPubkey(peerB.priv)

	peerA.sess, _ = NewSession(peerA.priv, peerB.pub)
	peerB.sess, _ = NewSession(peerB.priv, peerA.pub)

	packet, err := peerA.sess.ConstructHandshakeReq()
	if err != nil {
		t.Fatal("Couldn't construct handshake request:", err)
	}

	err = peerB.sess.ParseHandshakeReq(packet)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(peerB.sess.theirEphemPub, peerA.sess.ephemPub) {
		t.Fatal("Failed to record ephemeral keys"+
			"\nExpected:", peerA.sess.ephemPub,
			"\nActual:", peerB.sess.theirEphemPub)

	}

	if peerB.sess.created != peerA.sess.created {
		t.Fatal("Session creation mismatch:"+
			"\nExpected:", peerA.sess.created,
			"\nActual:", peerB.sess.created)
	}

}

func TestConstructHandshakeResp(t *testing.T) {
	priv, _ := base64.StdEncoding.DecodeString("0CLEtP7eYTsJ6IE9j01kqCU8Z+1cxF4UwmBCyxXVkFM=")
	pub, _ := base64.StdEncoding.DecodeString("xkNx31UWBNbosBFYBEvGYXbNgOqNPXGjThT79ELNBE8=")
	sess, _ := NewSession(priv, pub)
	sess.theirEphemPub = pub

	handshake, err := sess.ConstructHandshakeResp()
	if err != nil {
		t.Fatal(err)
	}

	if len(handshake) != handshakeRespSize {
		t.Fatal("Handshake is the wrong length:", len(handshake), "instead of", handshakeRespSize)
	}
}

func TestParseHandshakeResp(t *testing.T) {
	peerA := struct {
		sess *Session
		pub  []byte
		priv []byte
	}{}
	peerB := struct {
		sess *Session
		pub  []byte
		priv []byte
	}{}

	peerA.priv, _ = genPrivkey()
	peerA.pub, _ = genPubkey(peerA.priv)

	peerB.priv, _ = genPrivkey()
	peerB.pub, _ = genPubkey(peerB.priv)

	peerA.sess, _ = NewSession(peerA.priv, peerB.pub)
	peerB.sess, _ = NewSession(peerB.priv, peerA.pub)

	packet, _ := peerA.sess.ConstructHandshakeReq()

	_ = peerB.sess.ParseHandshakeReq(packet)

	packet, err := peerB.sess.ConstructHandshakeResp()
	if err != nil {
		t.Fatal("Error constructing handshake response")
	}

	err = peerA.sess.ParseHandshakeResp(packet)
	if err != nil {
		t.Fatal("Error parsing handshake response:", err)
	}
}

func TestDataExchange(t *testing.T) {
	peerA := struct {
		sess *Session
		pub  []byte
		priv []byte
	}{}
	peerB := struct {
		sess *Session
		pub  []byte
		priv []byte
	}{}

	message := []byte("Testing, testing.")

	peerA.priv, _ = genPrivkey()
	peerA.pub, _ = genPubkey(peerA.priv)

	peerB.priv, _ = genPrivkey()
	peerB.pub, _ = genPubkey(peerB.priv)

	peerA.sess, _ = NewSession(peerA.priv, peerB.pub)
	peerB.sess, _ = NewSession(peerB.priv, peerA.pub)

	packet, _ := peerA.sess.ConstructHandshakeReq()

	_ = peerB.sess.ParseHandshakeReq(packet)

	packet, _ = peerB.sess.ConstructHandshakeResp()

	_ = peerA.sess.ParseHandshakeResp(packet)

	encrypted, err := peerA.sess.EncryptPacket(message)
	if err != nil {
		t.Fatal("Error encrypting packet:", err)
	}

	decrypted, err := peerB.sess.DecryptPacket(encrypted)
	if err != nil {
		t.Fatal("Error decrypting packet", err)
	}
	if !bytes.Equal(decrypted, message) {
		t.Fatal("Decrypted messages are different.")
	}
}
