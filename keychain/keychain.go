package keychain

import (
	"context"
	"fmt"

	"github.com/jfxdev/sops-wrapper/keychain/aws"
	"github.com/jfxdev/sops-wrapper/keychain/azure"
	"github.com/jfxdev/sops-wrapper/keychain/entities"
	"github.com/jfxdev/sops-wrapper/keychain/gcp"
	"github.com/jfxdev/sops-wrapper/keychain/vault"

	"github.com/getsops/sops/v3/keys"
)

type KeyGroupFunc func(ctx context.Context, key entities.EncryptionKey) (result keys.MasterKey)

var keyStore = make(map[string]KeyGroupFunc)

func init() {
	keyStore[aws.Alias] = aws.NewKeyGroup
	keyStore[azure.Alias] = azure.NewKeyGroup
	keyStore[gcp.Alias] = gcp.NewKeyGroup
	keyStore[vault.Alias] = vault.NewKeyGroup
}

func KeyGroup(alias string) (result KeyGroupFunc, err error) {
	if _, ok := keyStore[alias]; !ok {
		return result, fmt.Errorf("the keygroup alias %s does not exists on catalog", alias)
	}
	return keyStore[alias], nil
}
