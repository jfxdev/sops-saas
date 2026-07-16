package age

import (
	"context"

	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keys"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

// Alias is the EncryptionKey.Platform value for age recipients.
const Alias = "age"

// NewKeyGroup builds an age MasterKey from key.ID, expected to be an age
// public recipient string ("age1..."). Unlike the KMS-backed key groups,
// age.MasterKeyFromRecipient validates the recipient and can fail, which is
// why KeyGroupFunc returns an error.
func NewKeyGroup(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey, err error) {
	masterKey, err := sopsage.MasterKeyFromRecipient(key.ID)
	if err != nil {
		// masterKey is a typed nil (*age.MasterKey)(nil) here — returning it
		// directly as the keys.MasterKey interface would make result != nil
		// to callers despite the error, so return an explicit nil interface.
		return nil, err
	}
	return masterKey, nil
}
