package sops

import (
	"context"
	"errors"
	"fmt"

	"github.com/jfxdev/sops-wrapper/keychain"
	"github.com/jfxdev/sops-wrapper/keychain/entities"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
)

type DataFormat string

const (
	FormatYAML DataFormat = "yaml"
	FormatJSON DataFormat = "json"
)

type Cipher interface {
	Decrypt(ctx context.Context, content []byte, format DataFormat) ([]byte, error)
	Encrypt(ctx context.Context, data []byte, config EncryptionConfig) ([]byte, error)
	Rotate(ctx context.Context, encryptedContent []byte, newConfig EncryptionConfig) ([]byte, error)
}

type cipher struct {
	keyServiceClient keyservice.KeyServiceClient
}

func NewCipher() Cipher {
	return &cipher{
		keyServiceClient: keyservice.NewLocalClient(),
	}
}

func (c *cipher) Decrypt(ctx context.Context, content []byte, format DataFormat) ([]byte, error) {
	if format != FormatYAML && format != FormatJSON {
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return decrypt.Data(content, string(format))
}

type EncryptionConfig struct {
	Format            DataFormat
	Keys              []entities.EncryptionKey
	UnencryptedSuffix string
	EncryptedSuffix   string
	UnencryptedRegex  string
	EncryptedRegex    string
	ShamirThreshold   int
}

func (c *cipher) Encrypt(ctx context.Context, content []byte, config EncryptionConfig) ([]byte, error) {
	var store common.Store
	storesConfig := sopsconfig.NewStoresConfig()
	switch config.Format {
	case FormatYAML:
		store = common.StoreForFormat(formats.Yaml, storesConfig)
	case FormatJSON:
		store = common.StoreForFormat(formats.Json, storesConfig)
	default:
		return nil, fmt.Errorf("unsupported format: %s", config.Format)
	}

	branches, err := store.LoadPlainFile(content)
	if err != nil {
		return nil, fmt.Errorf("failed to load plain file: %w", err)
	}

	var groups []sops.KeyGroup

	for _, k := range config.Keys {
		gfunc, err := keychain.KeyGroup(k.Platform)
		if err != nil {
			return nil, fmt.Errorf("failed to get keygroup for platform %s: %w", k.Platform, err)
		}

		masterKey, err := gfunc(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("failed to build master key for platform %s: %w", k.Platform, err)
		}

		groups = append(groups, sops.KeyGroup{masterKey})
	}

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
		[]keyservice.KeyServiceClient{c.keyServiceClient},
	)

	if len(errs) > 0 {
		return nil, fmt.Errorf("could not generate data key: %w", errors.Join(errs...))
	}

	encryptTreeOpts := common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	}
	err = common.EncryptTree(encryptTreeOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt tree: %w", err)
	}

	encBytes, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed to emit encrypted file: %w", err)
	}

	return encBytes, nil
}

func (c *cipher) Rotate(ctx context.Context, encryptedContent []byte, newConfig EncryptionConfig) ([]byte, error) {
	plainContent, err := c.Decrypt(ctx, encryptedContent, newConfig.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content during rotation: %w", err)
	}

	rotatedContent, err := c.Encrypt(ctx, plainContent, newConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt content with new keys: %w", err)
	}

	return rotatedContent, nil
}
