package azure

import (
	"context"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/azkv"
	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

const Alias = "azure/kv"

func NewKeyGroup(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey, err error) {
	masterKey, err := azkv.NewMasterKeyFromURL(key.ID)
	if err != nil {
		// masterKey is a typed nil (*azkv.MasterKey)(nil) here — returning it
		// directly as the keys.MasterKey interface would make result != nil
		// to callers despite the error, so return an explicit nil interface.
		return nil, err
	}
	return masterKey, nil
}
