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

func TestEncryptDecryptForest(t *testing.T) {
	for i := 1; i <= 10; i++ {
		acctree := makeTreeNodesAndKxN(i)
		attrs := makeNAttributes(99)
		M := ArbitraryGtPoint(32)

		mkey, pp, _ := Setup(100)

		dkey := KeyGen(acctree, mkey)
		c, _ := Encrypt(M, attrs, pp)

		M_decrypted, success := Decrypt(c, dkey)
		if !success {
			t.Errorf("Error: Decryption failed!")
		}

		if !M.IsEqual(M_decrypted) {
			t.Errorf("Error: Decrypt(Encrypt(M)) != M")
		}
	}
}

func TestEncryptDecryptDeepTree(t *testing.T) {
	twoleaves := make([]*act.AccessTreeNode, 2)
	twoleaves[0] = act.MakeLeaf(1)
	twoleaves[1] = act.MakeLeaf(2)
	acctree := act.MakeTree(
		act.MakeBranch(1,
			act.MakeBranch(3,
				act.MakeBranch(1,
					act.MakeBranch(2,
						twoleaves...,
					),
				), act.MakeLeaf(3), act.MakeLeaf(4),
			),
		),
	)

	for i := 100; i <= 100; i++ {
		attrs := makeNAttributes(99)
		M := ArbitraryGtPoint(32)

		mkey, pp, _ := Setup(100)

		dkey := KeyGen(acctree, mkey)
		c, _ := Encrypt(M, attrs, pp)

		M_decrypted, success := Decrypt(c, dkey)
		if !success {
			t.Errorf("Error: Decryption failed!")
		}

		if !M.IsEqual(M_decrypted) {
			t.Errorf("Error: Decrypt(Encrypt(M)) != M")
		}
	}
}

func TestEncrypt20AttributeTree(t *testing.T) {
	leaves := make([]*act.AccessTreeNode, 10)
	for i := 0; i < 10; i++ {
		leaves[i] = act.MakeLeaf(i + 1)
	}
	acctree := act.MakeTree(
		act.MakeBranch(5,
			act.MakeBranch(5,
				act.MakeBranch(3,
					act.MakeBranch(10,
						leaves...,
					), act.MakeLeaf(19), act.MakeLeaf(20),
				), act.MakeLeaf(11), act.MakeLeaf(12), act.MakeLeaf(13), act.MakeLeaf(14),
			), act.MakeLeaf(15), act.MakeLeaf(16), act.MakeLeaf(17), act.MakeLeaf(18),
		),
	)

	attrs := makeNAttributes(20)
	M := ArbitraryGtPoint(32)
	mkey, pp, _ := Setup(100)
	dkey := KeyGen(acctree, mkey)
	c, _ := Encrypt(M, attrs, pp)

	M_decrypted, success := Decrypt(c, dkey)
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

func TestEncryptDecryptForestNotSat(t *testing.T) {
	for i := 1; i < 20; i++ {
		acctree := makeTreeNodesAndKxN(i)
		attrs := makeNAttributes(0)
		M := ArbitraryGtPoint(32)

		mkey, pp, _ := Setup(100)

		dkey := KeyGen(acctree, mkey)
		c, _ := Encrypt(M, attrs, pp)

		_, success := Decrypt(c, dkey)
		if success {
			t.Errorf("Decryption using attributes not held by user succeeded")
		}
	}
}
