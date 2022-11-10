package main

import (
	"crypto/rand"
	"log"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type MasterKey struct {
	T []*bls.Scalar
	Y *bls.Scalar
}

type PublicParameters struct {
	BigT []*bls.G2
	BigY *bls.Gt
}

type AttributeSet = map[int]struct{}

type CipherText struct {
	attrs  AttributeSet
	EPrime *bls.Gt
	E      map[int]*bls.G2
}

func Setup(n int) (MasterKey, PublicParameters) {
	// Generate master key
	y := new(bls.Scalar)
	err := y.Random(rand.Reader) // Generate y /in Zp where p is order of G_1 and G_2
	if err != nil {
		log.Fatal("Error while generating master key:", err)
	}
	// n denotes the amount of attributes
	t := make([]*bls.Scalar, n)
	for attribute := 0; attribute < n; attribute++ {
		t[attribute] = new(bls.Scalar)
		t[attribute].Random(rand.Reader)
	}
	// Generate public parameters
	T := make([]*bls.G2, n)
	for attribute := 0; attribute < n; attribute++ {
		T[attribute] = new(bls.G2)
		T[attribute].ScalarMult(t[attribute], bls.G2Generator())
	}
	Y := bls.Pair(bls.G1Generator(), bls.G2Generator())
	Y.Exp(Y, y)
	return MasterKey{T: t, Y: y}, PublicParameters{BigT: T, BigY: Y}
}

func Encrypt(M *bls.Gt, attrs AttributeSet, PK PublicParameters) CipherText {
	s := new(bls.Scalar)
	err := s.Random(rand.Reader) // Generate s /in Zp
	if err != nil {
		log.Fatal("Error while generating s in encrypt:", err)
	}

	EPrime := new(bls.Gt)
	EPrime.Exp(PK.BigY, s)
	EPrime.Mul(EPrime, M)

	E := make(map[int]*bls.G2, len(attrs))
	for i := range attrs {
		E[i] = new(bls.G2)
		E[i].ScalarMult(s, PK.BigT[i])
	}

	return CipherText{attrs, EPrime, E}
}

func KeyGen() {

}

func Decrypt() {

}
