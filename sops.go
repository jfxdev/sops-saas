package sops

import (
	"errors"
	"fmt"

	"github.com/jfxdev/sops-saas/keychain"
	"github.com/jfxdev/sops-saas/keychain/entities"

	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/decrypt"
	"go.mozilla.org/sops/v3/keyservice"
	"go.mozilla.org/sops/v3/version"
)

const (
	formatYaml = "yaml"
	formatJson = "json"
)

type Cypher interface {
	Decrypt(content []byte, config string) ([]byte, error)
	Encrypt(data []byte, config EncryptionConfig) ([]byte, error)
}

type cypher struct{}

func NewCypher() Cypher {
	return &cypher{}
}

func (c *cypher) Decrypt(content []byte, format string) ([]byte, error) {
	return decrypt.Data(content, format)
}

type EncryptionConfig struct {
	Format            string
	Keys              []entities.EncryptionKey
	UnencryptedSuffix string
	EncryptedSuffix   string
	UnencryptedRegex  string
	EncryptedRegex    string
	ShamirThreshold   int
}

func (m *cypher) Encrypt(content []byte, config EncryptionConfig) (result []byte, err error) {
	var store common.Store
	switch config.Format {
	case formatYaml:
		store = common.StoreForFormat(formats.Yaml)
	default:
		store = common.StoreForFormat(formats.Json)
	}

	branches, err := store.LoadPlainFile(content)
	if err != nil {
		return
	}

	var groups []sops.KeyGroup
	var keyGroup sops.KeyGroup

	for _, k := range config.Keys {
		gfunc, err := keychain.KeyGroup(k.Platform)
		if err != nil {
			return result, err
		}

		keyGroup = append(keyGroup, gfunc(k))
	}

	groups = append(groups, keyGroup)

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:         groups,
			UnencryptedSuffix: config.UnencryptedSuffix,
			EncryptedSuffix:   config.EncryptedSuffix,
			UnencryptedRegex:  config.UnencryptedRegex,
			EncryptedRegex:    config.EncryptedRegex,
			Version:           version.Version,
			ShamirThreshold:   config.ShamirThreshold,
		},
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	)

	if len(errs) > 0 {
		return nil, errors.New(fmt.Sprint("Could not generate data key:", errs))
	}

	encryptTreeOpts := common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	}
	err = common.EncryptTree(encryptTreeOpts)
	if err != nil {
		return nil, err
	}

	return store.EmitEncryptedFile(tree)
}
