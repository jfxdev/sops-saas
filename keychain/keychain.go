package keychain

import (
	"fmt"

	"github.com/jfxdev/sops-saas/keychain/aws"
	"github.com/jfxdev/sops-saas/keychain/entities"
	"github.com/jfxdev/sops-saas/keychain/gcp"
	"github.com/jfxdev/sops-saas/keychain/vault"

	"go.mozilla.org/sops/keys"
)

type KeyGroupFunc func(key entities.EncryptionKey) (result keys.MasterKey)

var keyStore = make(map[string]KeyGroupFunc)

func init() {
	keyStore[aws.Alias] = aws.NewKeyGroup
	keyStore[gcp.Alias] = gcp.NewKeyGroup
	keyStore[vault.Alias] = vault.NewKeyGroup
}

func KeyGroup(alias string) (result KeyGroupFunc, err error) {
	if _, ok := keyStore[alias]; !ok {
		return result, fmt.Errorf("the keygroup alias %s does not exists on catalog", alias)
	}
	return keyStore[alias], nil
}
