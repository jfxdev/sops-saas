package vault

import (
	"context"

	"github.com/jfxdev/sops-wrapper/keychain/entities"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/hcvault"
)

const Alias = "vault/kms"

func NewKeyGroup(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey, err error) {
	return hcvault.NewMasterKey(
		key.Parameters["url"],
		key.Parameters["engine_path"],
		key.Parameters["key_path"],
	), nil
}
