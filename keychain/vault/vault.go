package vault

import (
	"github.com/jfxdev/sops-saas/keychain/entities"

	"go.mozilla.org/sops/keys"
	"go.mozilla.org/sops/v3/hcvault"
)

const Alias = "vault/kms"

func NewKeyGroup(key entities.EncryptionKey) (result keys.MasterKey) {
	result = hcvault.NewMasterKey(
		key.Parameters["url"],
		key.Parameters["engine_path"],
		key.Parameters["key_path"],
	)
	return
}
