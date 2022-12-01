package gpsw

import (
	"crypto/rand"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	act "github.com/kasperdi/Key-PolicyABE-golang/accesstree"
)

var Empty struct{}

func ArbitraryGtPoint(n int) *bls.Gt {
	M1_bytes := make([]byte, n)
	rand.Read(M1_bytes)
	G1 := new(bls.G1)
	G1.Hash(M1_bytes, nil)

	M2_bytes := make([]byte, n)
	rand.Read(M2_bytes)
	G2 := new(bls.G2)
	G2.Hash(M2_bytes, nil)

	return bls.Pair(G1, G2)
}

func TestEncryptDecrypt(t *testing.T) {
	M := ArbitraryGtPoint(32)

	MK, PP, err := Setup(3)
	if err != nil {
		t.Error(err)
	}

	aTree := act.MakeTree(act.MakeBranch(2,
		act.MakeLeaf(0),
		act.MakeLeaf(1),
	))
	D := KeyGen(aTree, MK)
	attrs := make(AttributeSet)
	attrs[0] = Empty
	attrs[1] = Empty

	C, err := Encrypt(M, attrs, PP)
	if err != nil {
		t.Error(err)
	}

	M_decrypted, success := Decrypt(C, D)
	if !success {
		t.Errorf("Error: Decryption failed!")
	}

	if !M.IsEqual(M_decrypted) {
		t.Errorf("Error: Decrypt(Encrypt(M)) != M")
	}

}

func TestEncryptDecryptTNotSat(t *testing.T) {
	M := ArbitraryGtPoint(32)

	MK, PP, err := Setup(3)
	if err != nil {
		t.Error(err)
	}

	aTree := act.MakeTree(act.MakeLeaf(0))
	D := KeyGen(aTree, MK)
	attrs := make(AttributeSet)

	C, err := Encrypt(M, attrs, PP)
	if err != nil {
		t.Error(err)
	}

	_, success := Decrypt(C, D)
	if success {
		t.Errorf("Decryption using attributes not held by user succeeded")
	}

}
