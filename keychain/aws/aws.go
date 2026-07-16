package aws

import (
	"context"
	"fmt"

	"github.com/jfxdev/sops-wrapper/keychain/entities"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
)

const Alias = "aws/kms"

func NewKeyGroup(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey, err error) {
	var id string
	if key.Role == "" {
		id = key.ID
	} else {
		id = fmt.Sprintf("%s+%s", key.ID, key.Role)
	}

	result = kms.NewMasterKeyFromArn(
		id,
		kms.ParseKMSContext(key.Context),
		"",
	)
	return result, nil
}
