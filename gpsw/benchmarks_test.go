package gpsw

import (
	"testing"

	act "github.com/kasperdi/Key-PolicyABE-golang/accesstree"
)

func runBenchmarkSetup(b *testing.B, n int) {
	for i := 0; i < b.N; i++ {
		Setup(n)
	}
}

func runBenchmarkExtract(b *testing.B, n int, tree act.AccessTree) {
	mkey, _, _ := Setup(n)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		KeyGen(tree, mkey)
	}
}

func runBenchmarkEncrypt(b *testing.B, n int, attrs map[int]struct{}) {
	M := ArbitraryGtPoint(32)

	_, pp, _ := Setup(n)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(M, attrs, pp)
	}
}

func runBenchmarkDecrypt(b *testing.B, n int, attrs map[int]struct{}, tree act.AccessTree) {
	M := ArbitraryGtPoint(32)

	mkey, pp, _ := Setup(n)

	dkey := KeyGen(tree, mkey)
	c, _ := Encrypt(M, attrs, pp)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(c, dkey)
	}
}

func makeAttrs(attrs ...int) map[int]struct{} {
	attrMap := make(map[int]struct{})

	for _, att := range attrs {
		attrMap[att] = Empty
	}

	return attrMap
}

func makeExampleTree() act.AccessTree {
	// should enable both point to point and role-based.
	// assuming each person can be identified by:
	// 1. their identity, or
	// 2. their role and location (or something like that).
	tree := act.MakeTree(
		act.MakeBranch(1,
			act.MakeLeaf(0),
			act.MakeBranch(2,
				act.MakeLeaf(1),
				act.MakeLeaf(2),
			),
		),
	)
	return tree
}

// =======================
// Scenario: small company
// =======================

const SC_ATTRIBUTES = 50

func BenchmarkSetupSC(b *testing.B) {
	runBenchmarkSetup(b, SC_ATTRIBUTES)
}

func BenchmarkExtractSC(b *testing.B) {
	runBenchmarkExtract(b, SC_ATTRIBUTES, makeExampleTree())
}

func BenchmarkEncryptSC(b *testing.B) {
	runBenchmarkEncrypt(b, SC_ATTRIBUTES, makeAttrs(1, 2))
}

func BenchmarkDecryptSC(b *testing.B) {
	runBenchmarkDecrypt(b, SC_ATTRIBUTES, makeAttrs(1, 2), makeExampleTree())
}

// ========================
// Scenario: larger company
// ========================

const LC_ATTRIBUTES = 5000

func BenchmarkSetupLC(b *testing.B) {
	runBenchmarkSetup(b, LC_ATTRIBUTES)
}

func BenchmarkExtractLC(b *testing.B) {
	runBenchmarkExtract(b, LC_ATTRIBUTES, makeExampleTree())
}

func BenchmarkEncryptLC(b *testing.B) {
	runBenchmarkEncrypt(b, LC_ATTRIBUTES, makeAttrs(1, 2))
}

func BenchmarkDecryptLC(b *testing.B) {
	runBenchmarkDecrypt(b, LC_ATTRIBUTES, makeAttrs(1, 2), makeExampleTree())
}

// ===========================
// Scenario: Aarhus University
// ===========================

const AU_ATTRIBUTES = 50000

func BenchmarkSetupG(b *testing.B) {
	runBenchmarkSetup(b, AU_ATTRIBUTES)
}

func BenchmarkExtractG(b *testing.B) {
	runBenchmarkExtract(b, AU_ATTRIBUTES, makeExampleTree())
}

func BenchmarkEncryptG(b *testing.B) {
	runBenchmarkEncrypt(b, AU_ATTRIBUTES, makeAttrs(1, 2))
}

func BenchmarkDecryptG(b *testing.B) {
	runBenchmarkDecrypt(b, AU_ATTRIBUTES, makeAttrs(1, 2), makeExampleTree())
}
