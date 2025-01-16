package gcp

import (
	"github.com/jfxdev/sops-saas/keychain/entities"

	"go.mozilla.org/sops/keys"
	"go.mozilla.org/sops/v3/gcpkms"
)

const Alias = "gcp/kms"

func NewKeyGroup(key entities.EncryptionKey) (result keys.MasterKey) {
	result = gcpkms.NewMasterKeyFromResourceID(key.ID)
	return
}
