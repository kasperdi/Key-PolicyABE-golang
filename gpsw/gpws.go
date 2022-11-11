package gpsw

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

type AccessTree struct {
	Root *AccessTreeNode
}

type AccessTreeNode struct {
	Attribute *int            // only exists if leaf
	Parent    *AccessTreeNode // only exists if not root
	Children  []*AccessTreeNode
	Index     int
	K         int
}

type DecryptionKey struct {
	D map[*AccessTreeNode]*bls.G1
	T AccessTree
}

type Polynomial []bls.Scalar

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

func KeyGen(tree AccessTree, mk MasterKey) DecryptionKey {

	// First choose q_x for each node x top down starting from the root
	polyMap := make(map[*AccessTreeNode]Polynomial)
	polyMap = GenPolyRecursive(mk.Y, tree.Root, polyMap)

	// Compute D_x
	Dxmap := make(map[*AccessTreeNode]*bls.G1)

	for key, val := range polyMap {
		// If node is leaf
		if len(key.Children) == 0 {

			i := *key.Attribute

			DxExponent := new(bls.Scalar)

			DxExponent.Inv(mk.T[i])
			DxExponent.Mul(EvalPoly(val, 0), DxExponent)

			Dx := new(bls.G1)
			Dx.ScalarMult(DxExponent, bls.G1Generator())
			Dxmap[key] = Dx
		}
	}

	return DecryptionKey{D: Dxmap, T: tree}

}

func GenPolyRecursive(q0 *bls.Scalar, x *AccessTreeNode, polyMap map[*AccessTreeNode]Polynomial) map[*AccessTreeNode]Polynomial {
	resMap := polyMap
	// degree of each node d_x = k_x - 1
	currentPoly := constructSecretPoly(*q0, x.K-1)
	resMap[x] = currentPoly

	for _, val := range x.Children {
		resMap = GenPolyRecursive(EvalPoly(currentPoly, val.Index), val, resMap)
	}

	return resMap
}

func EvalPoly(poly Polynomial, arg int) *bls.Scalar {
	argument := new(bls.Scalar)
	argument.SetUint64(uint64(arg))

	result := new(bls.Scalar)
	result.Set(&poly[0])
	for i := 1; i < len(poly); i++ {
		toAdd := new(bls.Scalar)
		toAdd.Mul(&poly[i], argument)

		result.Add(result, toAdd)
	}

	return result
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

func DecryptNode(C CipherText, D DecryptionKey, x *AccessTreeNode) (*bls.Gt, bool) {
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
	F := make(map[*AccessTreeNode]*bls.Gt)
	for _, z := range x.Children {
		Fz, success := DecryptNode(C, D, z)
		if success {
			F[z] = Fz
		}
	}

	// If not enough F_z acquired, i.e. less than k_x child nodes returned true when decrypting them
	if len(F) < x.K {
		return nil, false
	}

	// Create sets S_x, S'_x, this is not very clean code
	Sx := make(map[*AccessTreeNode]*bls.Gt)
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
		Fz_exp_lagrange.Exp(Fz, calculateLagrangeCoefficientZero(i_scalar, SxPrime))

		Fx.Mul(Fx, Fz_exp_lagrange)
	}

	return Fx, true
}

func calculateLagrangeCoefficientZero(i *bls.Scalar, s []*bls.Scalar) *bls.Scalar {
	res := new(bls.Scalar)
	res.SetOne()

	for _, j := range s {
		if i.IsEqual(j) == 1 {
			continue
		}

		negJ := new(bls.Scalar)
		negJ.Set(j)
		negJ.Neg()

		iMinusJInv := new(bls.Scalar)
		iMinusJInv.Sub(i, j)
		iMinusJInv.Inv(iMinusJInv)

		coeff := new(bls.Scalar)
		coeff.Mul(negJ, iMinusJInv)

		res.Mul(res, coeff)
	}

	return res
}

func constructSecretPoly(secret bls.Scalar, deg int) Polynomial {
	poly := make([]bls.Scalar, deg+1)
	poly[0] = secret
	for i := 1; i < deg+1; i++ {
		coefficient := new(bls.Scalar)
		coefficient.Random(rand.Reader)
		poly[i] = *coefficient
	}
	return poly
}
