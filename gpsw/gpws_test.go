package gpsw

import (
	"crypto/rand"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
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

	att0 := new(int)
	*att0 = 0
	att1 := new(int)
	*att1 = 1

	rootNode := AccessTreeNode{
		Parent:   nil,
		Children: make([]*AccessTreeNode, 0),
		Index:    1,
		K:        2,
	}

	childNode := AccessTreeNode{
		Attribute: att0,
		Parent:    &rootNode,
		Children:  make([]*AccessTreeNode, 0),
		Index:     1,
		K:         1,
	}

	childNode2 := AccessTreeNode{
		Attribute: att1,
		Parent:    &rootNode,
		Children:  make([]*AccessTreeNode, 0),
		Index:     2,
		K:         1,
	}

	rootNode.Children = append(rootNode.Children, &childNode)
	rootNode.Children = append(rootNode.Children, &childNode2)

	aTree := AccessTree{
		Root: &rootNode,
	}

	D := KeyGen(aTree, MK)

	attrs := make(AttributeSet)
	attrs[0] = Empty
	attrs[1] = Empty

	C := Encrypt(M, attrs, PP)
	M_decrypted, _ := Decrypt(C, D)

	if !M.IsEqual(M_decrypted) {
		t.Errorf("Error: Decrypt(Encrypt(M)) != M")
	}

}

func TestEncryptDecryptTNotSat(t *testing.T) {
	M := arbitraryGtPoint(32)

	MK, PP := Setup(3)

	att0 := new(int)
	*att0 = 0

	rootNode := AccessTreeNode{
		Attribute: att0,
		Parent:    nil,
		Children:  make([]*AccessTreeNode, 0),
		Index:     1,
		K:         1,
	}

	aTree := AccessTree{
		Root: &rootNode,
	}

	D := KeyGen(aTree, MK)

	attrs := make(AttributeSet)

	C := Encrypt(M, attrs, PP)
	_, success := Decrypt(C, D)

	if success {
		t.Errorf("Decryption using attributes not held by user succeeded")
	}

}
