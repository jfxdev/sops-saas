package aws

import (
	"fmt"

	"github.com/jfxdev/sops-saas/keychain/entities"

	"go.mozilla.org/sops/keys"
	"go.mozilla.org/sops/v3/kms"
)

const Alias = "aws/kms"

func NewKeyGroup(key entities.EncryptionKey) (result keys.MasterKey) {
	var id string
	if key.Role == "" {
	  id = key.ID
	} else {
	  id = fmt.Sprintf("%s+%s",key.ID,key.Role)
	}
	
	result = kms.NewMasterKeyFromArn(
		id,
		kms.ParseKMSContext(key.Context),
		"",
	)
	return
}
