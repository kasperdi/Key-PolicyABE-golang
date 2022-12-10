package secretsharing

import (
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

func TestEvalPolynomial(t *testing.T) {
	expected := make([]bls.Scalar, 3)
	poly := make(Polynomial, 8)
	poly[0].SetUint64(17)
	poly[1].SetUint64(73)
	poly[2].SetUint64(32)
	poly[3].SetUint64(12)
	poly[4].SetUint64(91)
	poly[5].SetUint64(47)
	poly[6].SetUint64(13)
	poly[7].SetUint64(4)

	expected[0].SetUint64(17)
	if poly.Eval(0).IsEqual(&expected[0]) == 0 {
		t.Errorf("Expected p(0) = 17, got %s", poly.Eval(0).String())
	}

	expected[1].SetUint64(5838241)
	if poly.Eval(7).IsEqual(&expected[1]) == 0 {
		t.Errorf("Expected p(7) = 5838241, got %s", poly.Eval(7).String())
	}

	poly2 := make(Polynomial, 3)
	poly2[0].SetUint64(3)
	poly2[1].SetUint64(8)
	poly2[2].SetUint64(5)

	expected[2].SetUint64(3 + 3*8 + 3*3*5)
	if poly2.Eval(3).IsEqual(&expected[2]) == 0 {
		t.Errorf("Expected p(3) = 72, got %s", poly.Eval(3).String())
	}
}

func TestSecretShare(t *testing.T) {
	secret := new(bls.Scalar)
	secret.SetUint64(42)
	poly := SecretShare(*secret, 23)
	if poly.Eval(0).IsEqual(secret) == 0 {
		t.Errorf("Expected p(0) = secret = 42, got %s", poly.Eval(0).String())
	}
}
