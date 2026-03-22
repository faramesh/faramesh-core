package dpr

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestComputeMerkleRootAndInclusionProofs(t *testing.T) {
	leaves := testLeafHashes("r0", "r1", "r2", "r3", "r4")

	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	if len(root) != sha256.Size {
		t.Fatalf("unexpected root length: %d", len(root))
	}

	for i := range leaves {
		proof, err := BuildInclusionProof(leaves, uint64(i))
		if err != nil {
			t.Fatalf("build inclusion proof %d: %v", i, err)
		}
		ok, err := VerifyInclusionProof(proof, root)
		if err != nil {
			t.Fatalf("verify inclusion proof %d: %v", i, err)
		}
		if !ok {
			t.Fatalf("expected proof %d to verify", i)
		}
	}
}

func TestInclusionProofTamperWrongSibling(t *testing.T) {
	leaves := testLeafHashes("a", "b", "c")
	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	proof, err := BuildInclusionProof(leaves, 1)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if len(proof.Hashes) == 0 {
		t.Fatal("expected non-empty siblings for tamper test")
	}

	bad := *proof
	bad.Hashes = append([]string(nil), proof.Hashes...)
	sibling, err := hex.DecodeString(bad.Hashes[0])
	if err != nil {
		t.Fatalf("decode sibling: %v", err)
	}
	sibling[0] ^= 0xff
	bad.Hashes[0] = hex.EncodeToString(sibling)

	ok, err := VerifyInclusionProof(&bad, root)
	if err != nil {
		t.Fatalf("verify tampered sibling: %v", err)
	}
	if ok {
		t.Fatal("expected tampered sibling proof to fail")
	}
}

func TestInclusionProofTamperWrongIndex(t *testing.T) {
	leaves := testLeafHashes("x", "y", "z", "w")
	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	proof, err := BuildInclusionProof(leaves, 1)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	bad := *proof
	bad.LeafIndex = 2
	ok, err := VerifyInclusionProof(&bad, root)
	if err != nil {
		t.Fatalf("verify wrong index: %v", err)
	}
	if ok {
		t.Fatal("expected wrong index proof to fail")
	}
}

func TestInclusionProofTamperWrongRoot(t *testing.T) {
	leaves := testLeafHashes("m", "n", "o")
	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		t.Fatalf("compute root: %v", err)
	}
	proof, err := BuildInclusionProof(leaves, 0)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	badRoot := make([]byte, len(root))
	copy(badRoot, root)
	badRoot[len(badRoot)-1] ^= 0x55

	ok, err := VerifyInclusionProof(proof, badRoot)
	if err != nil {
		t.Fatalf("verify wrong root: %v", err)
	}
	if ok {
		t.Fatal("expected wrong root to fail")
	}
}

func TestConsistencyProofValidOldToNew(t *testing.T) {
	leaves := testLeafHashes("p", "q", "r", "s", "t", "u")
	proof, err := BuildConsistencyProof(leaves, 3, 6)
	if err != nil {
		t.Fatalf("build consistency proof: %v", err)
	}
	ok, err := VerifyConsistencyProof(proof)
	if err != nil {
		t.Fatalf("verify consistency proof: %v", err)
	}
	if !ok {
		t.Fatal("expected consistency proof to verify")
	}
}

func TestConsistencyProofTamperedHashRejected(t *testing.T) {
	leaves := testLeafHashes("a0", "a1", "a2", "a3", "a4")
	proof, err := BuildConsistencyProof(leaves, 2, 5)
	if err != nil {
		t.Fatalf("build consistency proof: %v", err)
	}
	if len(proof.Hashes) == 0 {
		t.Fatal("expected non-empty consistency hashes for tamper test")
	}

	bad := *proof
	bad.Hashes = append([]string(nil), proof.Hashes...)
	h, err := hex.DecodeString(bad.Hashes[0])
	if err != nil {
		t.Fatalf("decode consistency hash: %v", err)
	}
	h[0] ^= 0xff
	bad.Hashes[0] = hex.EncodeToString(h)

	ok, err := VerifyConsistencyProof(&bad)
	if err != nil {
		t.Fatalf("verify tampered consistency proof: %v", err)
	}
	if ok {
		t.Fatal("expected tampered consistency proof to fail")
	}
}

func TestConsistencyProofWrongRootsRejected(t *testing.T) {
	leaves := testLeafHashes("k0", "k1", "k2", "k3")
	proof, err := BuildConsistencyProof(leaves, 2, 4)
	if err != nil {
		t.Fatalf("build consistency proof: %v", err)
	}

	badOld := *proof
	oldRoot, err := hex.DecodeString(badOld.FromRootHash)
	if err != nil {
		t.Fatalf("decode old root: %v", err)
	}
	oldRoot[0] ^= 0x0f
	badOld.FromRootHash = hex.EncodeToString(oldRoot)

	ok, err := VerifyConsistencyProof(&badOld)
	if err != nil {
		t.Fatalf("verify wrong old root: %v", err)
	}
	if ok {
		t.Fatal("expected wrong old root to fail")
	}

	badNew := *proof
	newRoot, err := hex.DecodeString(badNew.ToRootHash)
	if err != nil {
		t.Fatalf("decode new root: %v", err)
	}
	newRoot[len(newRoot)-1] ^= 0x0f
	badNew.ToRootHash = hex.EncodeToString(newRoot)

	ok, err = VerifyConsistencyProof(&badNew)
	if err != nil {
		t.Fatalf("verify wrong new root: %v", err)
	}
	if ok {
		t.Fatal("expected wrong new root to fail")
	}
}

func TestConsistencyProofBoundaryConditions(t *testing.T) {
	leaves := testLeafHashes("b0", "b1", "b2")

	same, err := BuildConsistencyProof(leaves, 3, 3)
	if err != nil {
		t.Fatalf("build same-size proof: %v", err)
	}
	if len(same.Hashes) != 0 {
		t.Fatalf("expected same-size proof to have no hashes, got %d", len(same.Hashes))
	}
	ok, err := VerifyConsistencyProof(same)
	if err != nil {
		t.Fatalf("verify same-size proof: %v", err)
	}
	if !ok {
		t.Fatal("expected same-size consistency proof to verify")
	}

	_, err = BuildConsistencyProof(leaves, 3, 2)
	if err == nil {
		t.Fatal("expected invalid size order error")
	}
}

func testLeafHashes(values ...string) [][]byte {
	out := make([][]byte, 0, len(values))
	for _, v := range values {
		sum := sha256.Sum256([]byte(v))
		out = append(out, sum[:])
	}
	return out
}
