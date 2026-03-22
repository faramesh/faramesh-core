package dpr

import (
	"encoding/hex"
	"time"
)

const ComplianceExportSchema = "faramesh.compliance.export.v1"

type ComplianceExportBundle struct {
	SchemaVersion string                        `json:"schema_version"`
	GeneratedAt   time.Time                     `json:"generated_at"`
	Status        ComplianceExportStatus        `json:"status"`
	Summary       ComplianceExportSummary       `json:"summary"`
	Checkpoint    ComplianceExportCheckpoint    `json:"checkpoint"`
	Proofs        ComplianceExportProofs        `json:"proofs"`
	Records       []ComplianceExportRecordEntry `json:"records"`
}

type ComplianceExportStatus struct {
	Success bool     `json:"success"`
	Errors  []string `json:"errors,omitempty"`
}

type ComplianceExportSummary struct {
	RecordCount int      `json:"record_count"`
	AgentIDs    []string `json:"agent_ids"`
}

type ComplianceExportCheckpoint struct {
	TreeSize     uint64 `json:"tree_size"`
	MerkleRoot   string `json:"merkle_root"`
	PreviousSize uint64 `json:"previous_size,omitempty"`
}

type ComplianceExportProofs struct {
	Inclusion  []ComplianceProofVerification `json:"inclusion"`
	Consistency *ComplianceProofVerification `json:"consistency,omitempty"`
}

type ComplianceProofVerification struct {
	Type    string `json:"type"`
	Success bool   `json:"success"`
	Details string `json:"details,omitempty"`
}

type ComplianceExportRecordEntry struct {
	RecordID   string    `json:"record_id"`
	AgentID    string    `json:"agent_id"`
	ToolID     string    `json:"tool_id"`
	CreatedAt  time.Time `json:"created_at"`
	RecordHash string    `json:"record_hash"`
}

// BuildComplianceExportBundle emits deterministic compliance evidence from DPR records.
func BuildComplianceExportBundle(records []*Record, now time.Time) (*ComplianceExportBundle, error) {
	leaves := make([][]byte, 0, len(records))
	entries := make([]ComplianceExportRecordEntry, 0, len(records))
	agentSeen := map[string]struct{}{}
	agentIDs := make([]string, 0, len(records))

	for _, rec := range records {
		if rec.RecordHash == "" {
			rec.ComputeHash()
		}
		h, err := hex.DecodeString(rec.RecordHash)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, h)
		entries = append(entries, ComplianceExportRecordEntry{
			RecordID:   rec.RecordID,
			AgentID:    rec.AgentID,
			ToolID:     rec.ToolID,
			CreatedAt:  rec.CreatedAt,
			RecordHash: rec.RecordHash,
		})
		if _, ok := agentSeen[rec.AgentID]; !ok {
			agentSeen[rec.AgentID] = struct{}{}
			agentIDs = append(agentIDs, rec.AgentID)
		}
	}

	root, err := ComputeMerkleRoot(leaves)
	if err != nil {
		return nil, err
	}
	rootHex := ""
	if len(root) > 0 {
		rootHex = hex.EncodeToString(root)
	}

	bundle := &ComplianceExportBundle{
		SchemaVersion: ComplianceExportSchema,
		GeneratedAt:   now.UTC(),
		Status:        ComplianceExportStatus{Success: true},
		Summary: ComplianceExportSummary{
			RecordCount: len(records),
			AgentIDs:    agentIDs,
		},
		Checkpoint: ComplianceExportCheckpoint{
			TreeSize:   uint64(len(records)),
			MerkleRoot: rootHex,
		},
		Proofs:  ComplianceExportProofs{Inclusion: make([]ComplianceProofVerification, 0, len(records))},
		Records: entries,
	}

	for i := range records {
		p, err := BuildInclusionProof(leaves, uint64(i))
		if err != nil {
			bundle.Status.Success = false
			bundle.Status.Errors = append(bundle.Status.Errors, err.Error())
			bundle.Proofs.Inclusion = append(bundle.Proofs.Inclusion, ComplianceProofVerification{
				Type:    "inclusion",
				Success: false,
				Details: err.Error(),
			})
			continue
		}
		ok, err := VerifyInclusionProof(p, root)
		ver := ComplianceProofVerification{Type: "inclusion", Success: ok}
		if err != nil {
			ver.Success = false
			ver.Details = err.Error()
			bundle.Status.Success = false
			bundle.Status.Errors = append(bundle.Status.Errors, err.Error())
		}
		bundle.Proofs.Inclusion = append(bundle.Proofs.Inclusion, ver)
	}

	if len(leaves) > 1 {
		fromSize := uint64(len(leaves) - 1)
		cp, err := BuildConsistencyProof(leaves, fromSize, uint64(len(leaves)))
		if err != nil {
			bundle.Status.Success = false
			bundle.Status.Errors = append(bundle.Status.Errors, err.Error())
			bundle.Proofs.Consistency = &ComplianceProofVerification{
				Type:    "consistency",
				Success: false,
				Details: err.Error(),
			}
		} else {
			ok, verr := VerifyConsistencyProof(cp)
			ver := &ComplianceProofVerification{Type: "consistency", Success: ok}
			if verr != nil {
				ver.Success = false
				ver.Details = verr.Error()
				bundle.Status.Success = false
				bundle.Status.Errors = append(bundle.Status.Errors, verr.Error())
			}
			bundle.Checkpoint.PreviousSize = fromSize
			bundle.Proofs.Consistency = ver
		}
	}
	return bundle, nil
}
