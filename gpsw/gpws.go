package gpsw

import (
	"crypto/rand"
	"fmt"
	"log"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	act "github.com/kasperdi/Key-PolicyABE-golang/accesstree"
	sss "github.com/kasperdi/Key-PolicyABE-golang/shamirsecretsharing"
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

type DecryptionKey struct {
	D map[*act.AccessTreeNode]*bls.G1
	T act.AccessTree
}

// Setup generates a set of public parameters and a master key for the given number of attributes.
func Setup(n int) (MasterKey, PublicParameters, error) {
	// Generate master key
	y := new(bls.Scalar)
	err := y.Random(rand.Reader) // Generate y /in Zp where p is order of G_1 and G_2
	if err != nil {
		return MasterKey{}, PublicParameters{}, fmt.Errorf("error while generating master key: %v", err)
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

	return MasterKey{T: t, Y: y}, PublicParameters{BigT: T, BigY: Y}, nil
}

func Encrypt(M *bls.Gt, attrs AttributeSet, PK PublicParameters) (CipherText, error) {
	s := new(bls.Scalar)
	err := s.Random(rand.Reader) // Generate s /in Zp
	if err != nil {
		return CipherText{}, fmt.Errorf("error while generating s in encrypt: %v", err)
	}

	EPrime := new(bls.Gt)
	EPrime.Exp(PK.BigY, s)
	EPrime.Mul(EPrime, M)

	E := make(map[int]*bls.G2, len(attrs))
	for i := range attrs {
		E[i] = new(bls.G2)
		E[i].ScalarMult(s, PK.BigT[i])
	}

	return CipherText{attrs, EPrime, E}, nil
}

func KeyGen(tree act.AccessTree, mk MasterKey) DecryptionKey {
	// First choose q_x for each node x top down starting from the root
	polyMap := sss.GenTreePolynomials(mk.Y, tree)

	// Compute D_x
	Dxmap := make(map[*act.AccessTreeNode]*bls.G1)

	for node, poly := range polyMap {
		// If node is leaf
		if len(node.Children) == 0 {

			i := *node.Attribute

			DxExponent := new(bls.Scalar)

			DxExponent.Inv(mk.T[i])
			DxExponent.Mul(poly.Eval(0), DxExponent)

			Dx := new(bls.G1)
			Dx.ScalarMult(DxExponent, bls.G1Generator())
			Dxmap[node] = Dx
		}
	}

	return DecryptionKey{D: Dxmap, T: tree}

}

func Decrypt(C CipherText, D DecryptionKey) (*bls.Gt, bool) {
	F_Root, success := DecryptNode(C, D, D.T.Root)
	if !success {
		return nil, false
	}
	result := new(bls.Gt)
	result.Inv(F_Root)
	result.Mul(result, C.EPrime)
	return result, true

}

func DecryptNode(C CipherText, D DecryptionKey, x *act.AccessTreeNode) (*bls.Gt, bool) {
	if x.Attribute != nil { // Node is a leaf node
		i := *x.Attribute
		_, contains := C.attrs[i]
		if contains {
			return bls.Pair(D.D[x], C.E[i]), true
		} else {
			return nil, false
		}

	}
	// Otherwise recurse
	F := make(map[*act.AccessTreeNode]*bls.Gt)
	for _, z := range x.Children {
		Fz, success := DecryptNode(C, D, z)
		if success {
			F[z] = Fz
			if len(F) >= x.K {
				// if we have enough, stop looking
				break
			}
		}
	}

	// If not enough F_z acquired, i.e. less than k_x child nodes returned true when decrypting them
	if len(F) < x.K {
		log.Printf("NEEDED %d nodes but got %d", x.K, len(F))
		return nil, false
	}

	// Create sets S_x, S'_x, this is not very clean code
	Sx := make(map[*act.AccessTreeNode]*bls.Gt)
	SxPrime := make([]*bls.Scalar, 0)
	for z, Fz := range F {
		Sx[z] = Fz

		index_z_scalar := new(bls.Scalar)
		index_z_scalar.SetUint64(uint64(z.Index))
		SxPrime = append(SxPrime, index_z_scalar)

		if len(Sx) == x.K {
			break
		}
	}

	// Compute and return Fx
	Fx := new(bls.Gt)
	Fx.SetIdentity()

	for z, Fz := range Sx {
		i_scalar := new(bls.Scalar)
		i_scalar.SetUint64(uint64(z.Index))

		Fz_exp_lagrange := new(bls.Gt)
		Fz_exp_lagrange.Exp(Fz, sss.CalculateLagrangeCoefficientZero(i_scalar, SxPrime))

		Fx.Mul(Fx, Fz_exp_lagrange)
	}

	return Fx, true
}
