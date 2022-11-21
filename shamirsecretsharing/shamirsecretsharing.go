package shamirsecretsharing

import (
	"crypto/rand"
	"math"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	act "github.com/kasperdi/Key-PolicyABE-golang/accesstree"
)

type Polynomial []bls.Scalar
type TreePolynomials map[*act.AccessTreeNode]Polynomial

func GenTreePolynomials(Y *bls.Scalar, T act.AccessTree) TreePolynomials {
	polyMap := make(TreePolynomials)
	return GenTreePolynomialsRec(Y, T.Root, polyMap)
}

func GenTreePolynomialsRec(q0 *bls.Scalar, x *act.AccessTreeNode, polyMap TreePolynomials) TreePolynomials {
	resMap := polyMap
	// degree of each node d_x = k_x - 1
	currentPoly := SecretShare(*q0, x.K-1)
	resMap[x] = currentPoly

	for _, val := range x.Children {
		resMap = GenTreePolynomialsRec(currentPoly.Eval(val.Index), val, resMap)
	}

	return resMap
}

func (p Polynomial) Eval(arg int) *bls.Scalar {
	result := new(bls.Scalar)
	result.Set(&p[0])
	for i := 1; i < len(p); i++ {
		X_exp_i_uint := uint64(math.Pow(float64(arg), float64(i)))
		X_exp_i := new(bls.Scalar)
		X_exp_i.SetUint64(X_exp_i_uint)

		toAdd := new(bls.Scalar)
		toAdd.Mul(&p[i], X_exp_i)
		result.Add(result, toAdd)
	}

	return result
}

func CalculateLagrangeCoefficientZero(i *bls.Scalar, s []*bls.Scalar) *bls.Scalar {
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

func SecretShare(secret bls.Scalar, deg int) Polynomial {
	poly := make([]bls.Scalar, deg+1)
	poly[0] = secret
	for i := 1; i < deg+1; i++ {
		coefficient := new(bls.Scalar)
		coefficient.Random(rand.Reader)
		poly[i] = *coefficient
	}
	return poly
}
