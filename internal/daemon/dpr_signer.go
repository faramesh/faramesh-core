package daemon

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"go.uber.org/zap"
)

func (d *Daemon) configureDPRSigner() dpr.Signer {
	if d == nil {
		return nil
	}
	kmsName := strings.TrimSpace(d.cfg.DPRKMSProvider)
	if kmsName == "" && d.providerReg != nil {
		kmsName, _ = d.providerReg.FirstKMSClient()
	}
	if kmsName != "" && d.providerReg != nil {
		client := d.providerReg.KMSClient(kmsName)
		if client != nil {
			signer, err := dpr.NewProviderKMSSigner(client, strings.TrimSpace(d.cfg.DPRKMSKeyRef))
			if err != nil {
				d.log.Warn("provider kms signer", zap.Error(err))
			} else {
				d.log.Info("configured provider KMS DPR signer", zap.String("provider", kmsName))
				return signer
			}
		}
	}

	ds := strings.TrimSpace(d.cfg.DPRSigner)
	if ds == "" || ds == "file" {
		privPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.key")
		pubPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.pub")
		privBytes, err := os.ReadFile(privPath)
		if err != nil {
			d.log.Warn("DPR signer private key not found; continuing without signer", zap.String("priv_path", privPath), zap.Error(err))
			return nil
		}
		pubBytes, err := os.ReadFile(pubPath)
		if err != nil {
			d.log.Warn("DPR signer public key not found; continuing without signer", zap.String("pub_path", pubPath), zap.Error(err))
			return nil
		}
		fs := dpr.NewFileSigner(privBytes, pubBytes)
		d.log.Info("configured file-based DPR signer", zap.String("data_dir", d.cfg.DataDir))
		return fs
	}
	if strings.HasPrefix(ds, "localkms://") {
		keyID := strings.TrimPrefix(ds, "localkms://")
		if keyID == "" {
			return nil
		}
		lks, err := dpr.NewLocalKMSSigner(d.cfg.DataDir, keyID)
		if err != nil {
			d.log.Warn("configure local-kms signer failed", zap.Error(err))
			return nil
		}
		d.log.Info("configured local-kms DPR signer", zap.String("key_id", keyID))
		return lks
	}
	if ds != "" {
		signer, err := dpr.ConstructSignerFromURI(ds, d.cfg.DataDir)
		if err != nil {
			d.log.Warn("kms uri signer failed", zap.String("dpr_signer", ds), zap.Error(err))
			return nil
		}
		d.log.Info("configured KMS URI DPR signer", zap.String("dpr_signer", ds))
		return signer
	}
	return nil
}
