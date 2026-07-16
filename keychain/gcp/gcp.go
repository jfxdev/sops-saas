package gcp

import (
	"context"

	"github.com/jfxdev/sops-wrapper/keychain/entities"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/gcpkms"
)

const Alias = "gcp/kms"

func NewKeyGroup(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey, err error) {
	return gcpkms.NewMasterKeyFromResourceID(key.ID), nil
}
