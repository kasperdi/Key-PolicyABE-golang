package gpsw

import (
	"crypto/rand"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	act "github.com/kasperdi/Key-PolicyABE-golang/accesstree"
)

var Empty struct{}

func arbitraryGtPoint(n int) *bls.Gt {
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
	M := arbitraryGtPoint(32)

	MK, PP := Setup(3)
	aTree := act.MakeTree(act.MakeBranch(2,
		act.MakeLeaf(0),
		act.MakeLeaf(1),
	))
	D := KeyGen(aTree, MK)
	attrs := make(AttributeSet)
	attrs[0] = Empty
	attrs[1] = Empty
	C := Encrypt(M, attrs, PP)
	M_decrypted, success := Decrypt(C, D)
	if !success {
		t.Errorf("Error: Decryption failed!")
	}

	if !M.IsEqual(M_decrypted) {
		t.Errorf("Error: Decrypt(Encrypt(M)) != M")
	}

}

func TestEncryptDecryptTNotSat(t *testing.T) {
	M := arbitraryGtPoint(32)

	MK, PP := Setup(3)
	aTree := act.MakeTree(act.MakeLeaf(0))
	D := KeyGen(aTree, MK)
	attrs := make(AttributeSet)

	C := Encrypt(M, attrs, PP)
	_, success := Decrypt(C, D)
	if success {
		t.Errorf("Decryption using attributes not held by user succeeded")
	}

}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup(2)
	}
}

func BenchmarkExtract(b *testing.B) {
	mkey, _ := Setup(2)

	tree := act.MakeTree(act.MakeBranch(2,
		act.MakeLeaf(0),
		act.MakeLeaf(1),
	))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KeyGen(tree, mkey)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	M := arbitraryGtPoint(32)

	_, pp := Setup(2)

	attrs := make(map[int]struct{})
	attrs[0] = Empty
	attrs[1] = Empty

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(M, attrs, pp)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	M := arbitraryGtPoint(32)

	attrs := make(map[int]struct{})
	attrs[0] = Empty
	attrs[1] = Empty

	mkey, pp := Setup(2)

	tree := act.MakeTree(act.MakeBranch(2,
		act.MakeLeaf(0),
		act.MakeLeaf(1),
	))

	dID := KeyGen(tree, mkey)
	c := Encrypt(M, attrs, pp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(c, dID)
	}
}
