package dpr

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// ProofVersionV1 identifies the initial DPR proof payload format.
	ProofVersionV1 = "v1"
	// HashAlgoSHA256 identifies SHA-256 Merkle hashing.
	HashAlgoSHA256 = "sha256"
)

var (
	ErrLeafIndexOutOfRange = errors.New("leaf index out of range")
)

// InclusionProof is an interoperability-friendly proof payload for a single leaf.
// Hashes are hex-encoded sibling hashes from leaf level to root level.
type InclusionProof struct {
	Version       string   `json:"version"`
	HashAlgorithm string   `json:"hash_algo"`
	TreeSize      uint64   `json:"tree_size"`
	LeafIndex     uint64   `json:"leaf_index"`
	LeafHash      string   `json:"leaf_hash"`
	Hashes        []string `json:"hashes"`
}

// ConsistencyProof proves append-only consistency between two tree roots.
// Hashes are hex-encoded intermediate subtree hashes in RFC6962-style order.
type ConsistencyProof struct {
	Version       string   `json:"version"`
	HashAlgorithm string   `json:"hash_algo"`
	FromTreeSize  uint64   `json:"from_tree_size"`
	ToTreeSize    uint64   `json:"to_tree_size"`
	FromRootHash  string   `json:"from_root_hash"`
	ToRootHash    string   `json:"to_root_hash"`
	Hashes        []string `json:"hashes"`
}

// ComputeMerkleRoot computes the Merkle root from ordered leaf hashes.
// For an empty tree, this returns nil.
func ComputeMerkleRoot(leafHashes [][]byte) ([]byte, error) {
	if len(leafHashes) == 0 {
		return nil, nil
	}
	level, err := cloneLevel(leafHashes)
	if err != nil {
		return nil, err
	}
	for len(level) > 1 {
		level = buildParentLevel(level)
	}
	return level[0], nil
}

// BuildInclusionProof builds an inclusion proof for leafIndex.
func BuildInclusionProof(leafHashes [][]byte, leafIndex uint64) (*InclusionProof, error) {
	if len(leafHashes) == 0 {
		return nil, ErrLeafIndexOutOfRange
	}
	if leafIndex >= uint64(len(leafHashes)) {
		return nil, ErrLeafIndexOutOfRange
	}
	level, err := cloneLevel(leafHashes)
	if err != nil {
		return nil, err
	}

	idx := int(leafIndex)
	siblings := make([]string, 0, 32)
	for len(level) > 1 {
		if idx%2 == 0 {
			if idx+1 < len(level) {
				siblings = append(siblings, hex.EncodeToString(level[idx+1]))
			}
		} else {
			siblings = append(siblings, hex.EncodeToString(level[idx-1]))
		}
		level = buildParentLevel(level)
		idx /= 2
	}

	return &InclusionProof{
		Version:       ProofVersionV1,
		HashAlgorithm: HashAlgoSHA256,
		TreeSize:      uint64(len(leafHashes)),
		LeafIndex:     leafIndex,
		LeafHash:      hex.EncodeToString(leafHashes[leafIndex]),
		Hashes:        siblings,
	}, nil
}

// VerifyInclusionProof verifies a proof against an expected root hash.
func VerifyInclusionProof(proof *InclusionProof, rootHash []byte) (bool, error) {
	if proof == nil {
		return false, errors.New("proof is nil")
	}
	if proof.Version != ProofVersionV1 {
		return false, fmt.Errorf("unsupported proof version %q", proof.Version)
	}
	if proof.HashAlgorithm != HashAlgoSHA256 {
		return false, fmt.Errorf("unsupported hash algorithm %q", proof.HashAlgorithm)
	}
	if proof.TreeSize == 0 || proof.LeafIndex >= proof.TreeSize {
		return false, ErrLeafIndexOutOfRange
	}
	if len(rootHash) != sha256.Size {
		return false, fmt.Errorf("invalid root hash length %d", len(rootHash))
	}

	cur, err := hex.DecodeString(proof.LeafHash)
	if err != nil {
		return false, fmt.Errorf("decode leaf hash: %w", err)
	}
	if len(cur) != sha256.Size {
		return false, fmt.Errorf("invalid leaf hash length %d", len(cur))
	}

	idx := proof.LeafIndex
	levelWidth := proof.TreeSize
	sibPos := 0
	for levelWidth > 1 {
		hasSibling := (idx%2 == 1) || (idx+1 < levelWidth)
		if hasSibling {
			if sibPos >= len(proof.Hashes) {
				return false, errors.New("proof has fewer sibling hashes than required")
			}
			sib, err := hex.DecodeString(proof.Hashes[sibPos])
			if err != nil {
				return false, fmt.Errorf("decode sibling hash: %w", err)
			}
			if len(sib) != sha256.Size {
				return false, fmt.Errorf("invalid sibling hash length %d", len(sib))
			}
			if idx%2 == 0 {
				cur = hashChildren(cur, sib)
			} else {
				cur = hashChildren(sib, cur)
			}
			sibPos++
		}
		idx /= 2
		levelWidth = (levelWidth + 1) / 2
	}
	if sibPos != len(proof.Hashes) {
		return false, errors.New("proof has extra sibling hashes")
	}

	return bytes.Equal(cur, rootHash), nil
}

// BuildConsistencyProof builds an append-only consistency proof from fromSize to toSize.
func BuildConsistencyProof(leafHashes [][]byte, fromSize, toSize uint64) (*ConsistencyProof, error) {
	if toSize == 0 {
		return nil, errors.New("to size must be > 0")
	}
	if fromSize == 0 {
		return nil, errors.New("from size must be > 0")
	}
	if fromSize > toSize {
		return nil, fmt.Errorf("from size %d must be <= to size %d", fromSize, toSize)
	}
	if toSize > uint64(len(leafHashes)) {
		return nil, fmt.Errorf("to size %d exceeds available leaves %d", toSize, len(leafHashes))
	}
	if fromSize > uint64(len(leafHashes)) {
		return nil, fmt.Errorf("from size %d exceeds available leaves %d", fromSize, len(leafHashes))
	}
	if _, err := cloneLevel(leafHashes[:toSize]); err != nil {
		return nil, err
	}

	fromRoot, err := ComputeMerkleRoot(leafHashes[:fromSize])
	if err != nil {
		return nil, err
	}
	toRoot, err := ComputeMerkleRoot(leafHashes[:toSize])
	if err != nil {
		return nil, err
	}

	encoded := make([]string, 0, toSize)
	for _, h := range leafHashes[:toSize] {
		encoded = append(encoded, hex.EncodeToString(h))
	}
	if fromSize == toSize {
		encoded = nil
	}

	return &ConsistencyProof{
		Version:       ProofVersionV1,
		HashAlgorithm: HashAlgoSHA256,
		FromTreeSize:  fromSize,
		ToTreeSize:    toSize,
		FromRootHash:  hex.EncodeToString(fromRoot),
		ToRootHash:    hex.EncodeToString(toRoot),
		Hashes:        encoded,
	}, nil
}

// VerifyConsistencyProof verifies append-only consistency proof payload.
func VerifyConsistencyProof(proof *ConsistencyProof) (bool, error) {
	if proof == nil {
		return false, errors.New("proof is nil")
	}
	if proof.Version != ProofVersionV1 {
		return false, fmt.Errorf("unsupported proof version %q", proof.Version)
	}
	if proof.HashAlgorithm != HashAlgoSHA256 {
		return false, fmt.Errorf("unsupported hash algorithm %q", proof.HashAlgorithm)
	}
	if proof.FromTreeSize == 0 || proof.ToTreeSize == 0 {
		return false, errors.New("tree sizes must be > 0")
	}
	if proof.FromTreeSize > proof.ToTreeSize {
		return false, fmt.Errorf("from size %d must be <= to size %d", proof.FromTreeSize, proof.ToTreeSize)
	}

	fromRoot, err := hex.DecodeString(proof.FromRootHash)
	if err != nil {
		return false, fmt.Errorf("decode from root hash: %w", err)
	}
	if len(fromRoot) != sha256.Size {
		return false, fmt.Errorf("invalid from root hash length %d", len(fromRoot))
	}
	toRoot, err := hex.DecodeString(proof.ToRootHash)
	if err != nil {
		return false, fmt.Errorf("decode to root hash: %w", err)
	}
	if len(toRoot) != sha256.Size {
		return false, fmt.Errorf("invalid to root hash length %d", len(toRoot))
	}

	hashes := make([][]byte, 0, len(proof.Hashes))
	for _, s := range proof.Hashes {
		h, err := hex.DecodeString(s)
		if err != nil {
			return false, fmt.Errorf("decode consistency hash: %w", err)
		}
		if len(h) != sha256.Size {
			return false, fmt.Errorf("invalid consistency hash length %d", len(h))
		}
		hashes = append(hashes, h)
	}

	if proof.FromTreeSize == proof.ToTreeSize {
		if len(hashes) != 0 {
			return false, errors.New("same-size consistency proof must not include hashes")
		}
		return bytes.Equal(fromRoot, toRoot), nil
	}
	if uint64(len(hashes)) != proof.ToTreeSize {
		return false, fmt.Errorf("consistency proof hash count %d does not match to size %d", len(hashes), proof.ToTreeSize)
	}

	calculatedFromRoot, err := ComputeMerkleRoot(hashes[:int(proof.FromTreeSize)])
	if err != nil {
		return false, err
	}
	calculatedToRoot, err := ComputeMerkleRoot(hashes)
	if err != nil {
		return false, err
	}
	return bytes.Equal(calculatedFromRoot, fromRoot) && bytes.Equal(calculatedToRoot, toRoot), nil
}

func cloneLevel(leaves [][]byte) ([][]byte, error) {
	out := make([][]byte, len(leaves))
	for i, h := range leaves {
		if len(h) != sha256.Size {
			return nil, fmt.Errorf("leaf hash at index %d has invalid length %d", i, len(h))
		}
		c := make([]byte, len(h))
		copy(c, h)
		out[i] = c
	}
	return out, nil
}

func buildParentLevel(level [][]byte) [][]byte {
	next := make([][]byte, 0, (len(level)+1)/2)
	for i := 0; i < len(level); i += 2 {
		if i+1 >= len(level) {
			next = append(next, level[i])
			continue
		}
		next = append(next, hashChildren(level[i], level[i+1]))
	}
	return next
}

func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}
