package azure

import (
	"context"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/azkv"
	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

const Alias = "azure/kv"

func NewKeyGroup(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey) {
	// azkv.NewMasterKeyFromURL returns (MasterKey, error)
	result, _ = azkv.NewMasterKeyFromURL(key.ID)
	return
}
