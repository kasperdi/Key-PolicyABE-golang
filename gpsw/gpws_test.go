package gpsw

import (
	"bytes"
	"crypto/rand"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

var Empty struct{}

func TestEncryptDecrypt(t *testing.T) {
	M_bytes := make([]byte, 32)
	rand.Read(M_bytes)

	M := new(bls.Gt)
	M.UnmarshalBinary(M_bytes)

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
	attrs[1] = Empty
	attrs[0] = Empty

	C := Encrypt(M, attrs, PP)

	M_decrypted, _ := Decrypt(C, D)
	M_decrypted_bytes, _ := M_decrypted.MarshalBinary()

	if !bytes.Equal(M_bytes, M_decrypted_bytes) {
		t.Errorf("Error: Decrypt(Encrypt(M)) != M")
	}

}
