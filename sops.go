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
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/version"
)

type DataFormat string

const (
	FormatYAML   DataFormat = "yaml"
	FormatJSON   DataFormat = "json"
	FormatDotenv DataFormat = "dotenv"
	FormatINI    DataFormat = "ini"
	FormatBinary DataFormat = "binary"
)

type Cipher interface {
	Decrypt(ctx context.Context, content []byte, format DataFormat) ([]byte, error)
	Encrypt(ctx context.Context, data []byte, config EncryptionConfig) ([]byte, error)
	Rotate(ctx context.Context, encryptedContent []byte, newConfig EncryptionConfig) ([]byte, error)
	UpdateKeys(ctx context.Context, encryptedContent []byte, newConfig EncryptionConfig) ([]byte, error)
	ReadEncryptionContexts(content []byte, format DataFormat) ([]EncryptionContext, error)
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
	if _, err := storeForFormat(format); err != nil {
		return nil, fmt.Errorf("unsupported format: %s", format)
	}

	return decrypt.Data(content, string(format))
}

type EncryptionConfig struct {
	Format DataFormat
	// Keys is a legacy shorthand for a single key group. All keys in the group
	// are alternatives: any one of them can decrypt the secret. It cannot be
	// used together with KeyGroups.
	Keys []entities.EncryptionKey
	// KeyGroups defines SOPS key groups. One key from each required group is
	// needed to recover the data key; ShamirThreshold controls the quorum.
	KeyGroups               [][]entities.EncryptionKey
	UnencryptedSuffix       string
	EncryptedSuffix         string
	UnencryptedRegex        string
	EncryptedRegex          string
	UnencryptedCommentRegex string
	EncryptedCommentRegex   string
	MACOnlyEncrypted        bool
	ShamirThreshold         int
}

// EncryptionContext identifies the AWS KMS encryption context attached to a
// master key in a SOPS file. The context is part of the file's plaintext
// metadata; reading it does not decrypt or authenticate the file.
//
// SOPS currently supports encryption contexts only for AWS KMS keys.
type EncryptionContext struct {
	Platform string
	KeyID    string
	Context  map[string]string
}

// ReadEncryptionContexts reads AWS KMS encryption contexts from a SOPS file
// without decrypting its contents. The returned metadata must not be used as
// an authorization decision by itself; enforce required contexts in AWS KMS
// key policies or IAM policies.
func (c *cipher) ReadEncryptionContexts(content []byte, format DataFormat) ([]EncryptionContext, error) {
	store, err := storeForFormat(format)
	if err != nil {
		return nil, err
	}

	tree, err := store.LoadEncryptedFile(content)
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted file: %w", err)
	}

	var contexts []EncryptionContext
	for _, group := range tree.Metadata.KeyGroups {
		for _, masterKey := range group {
			kmsKey, ok := masterKey.(*kms.MasterKey)
			if !ok {
				continue
			}

			context := make(map[string]string, len(kmsKey.EncryptionContext))
			for name, value := range kmsKey.EncryptionContext {
				if value != nil {
					context[name] = *value
				}
			}

			contexts = append(contexts, EncryptionContext{
				Platform: "aws/kms",
				KeyID:    kmsKey.Arn,
				Context:  context,
			})
		}
	}

	return contexts, nil
}

func (c *cipher) Encrypt(ctx context.Context, content []byte, config EncryptionConfig) ([]byte, error) {
	store, err := storeForFormat(config.Format)
	if err != nil {
		return nil, err
	}

	branches, err := store.LoadPlainFile(content)
	if err != nil {
		return nil, fmt.Errorf("failed to load plain file: %w", err)
	}

	groups, err := buildKeyGroups(ctx, config)
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:               groups,
			UnencryptedSuffix:       config.UnencryptedSuffix,
			EncryptedSuffix:         config.EncryptedSuffix,
			UnencryptedRegex:        config.UnencryptedRegex,
			EncryptedRegex:          config.EncryptedRegex,
			UnencryptedCommentRegex: config.UnencryptedCommentRegex,
			EncryptedCommentRegex:   config.EncryptedCommentRegex,
			MACOnlyEncrypted:        config.MACOnlyEncrypted,
			Version:                 version.Version,
			ShamirThreshold:         config.ShamirThreshold,
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

// UpdateKeys replaces the SOPS master keys and re-encrypts the existing data
// key for them. It does not decrypt or re-encrypt the secret values and does
// not generate a new data key. At least one existing master key must be able
// to decrypt the file's current data key.
func (c *cipher) UpdateKeys(ctx context.Context, encryptedContent []byte, newConfig EncryptionConfig) ([]byte, error) {
	store, err := storeForFormat(newConfig.Format)
	if err != nil {
		return nil, err
	}

	tree, err := store.LoadEncryptedFile(encryptedContent)
	if err != nil {
		return nil, fmt.Errorf("failed to load encrypted file: %w", err)
	}

	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{c.keyServiceClient}, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve existing data key: %w", err)
	}

	groups, err := buildKeyGroups(ctx, newConfig)
	if err != nil {
		return nil, err
	}
	tree.Metadata.KeyGroups = groups
	tree.Metadata.ShamirThreshold = newConfig.ShamirThreshold

	errs := tree.Metadata.UpdateMasterKeysWithKeyServices(
		dataKey, []keyservice.KeyServiceClient{c.keyServiceClient},
	)
	if len(errs) > 0 {
		return nil, fmt.Errorf("could not update master keys: %w", errors.Join(errs...))
	}

	updatedContent, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("failed to emit encrypted file: %w", err)
	}
	return updatedContent, nil
}

func buildKeyGroups(ctx context.Context, config EncryptionConfig) ([]sops.KeyGroup, error) {
	if len(config.Keys) > 0 && len(config.KeyGroups) > 0 {
		return nil, errors.New("Keys and KeyGroups cannot be used together")
	}

	keyGroups := config.KeyGroups
	if len(keyGroups) == 0 && len(config.Keys) > 0 {
		keyGroups = [][]entities.EncryptionKey{config.Keys}
	}
	if len(keyGroups) == 0 {
		return nil, errors.New("at least one key group is required")
	}
	if len(keyGroups) == 1 && config.ShamirThreshold != 0 {
		return nil, errors.New("ShamirThreshold requires at least two key groups")
	}
	if len(keyGroups) > 1 && (config.ShamirThreshold < 0 || config.ShamirThreshold == 1 || config.ShamirThreshold > len(keyGroups)) {
		return nil, fmt.Errorf("ShamirThreshold must be 0 or between 2 and %d", len(keyGroups))
	}

	groups := make([]sops.KeyGroup, 0, len(keyGroups))
	for index, group := range keyGroups {
		if len(group) == 0 {
			return nil, fmt.Errorf("key group %d cannot be empty", index)
		}

		masterKeys := make(sops.KeyGroup, 0, len(group))
		for _, key := range group {
			gfunc, err := keychain.KeyGroup(key.Platform)
			if err != nil {
				return nil, fmt.Errorf("failed to get keygroup for platform %s: %w", key.Platform, err)
			}

			masterKey, err := gfunc(ctx, key)
			if err != nil {
				return nil, fmt.Errorf("failed to build master key for platform %s: %w", key.Platform, err)
			}
			masterKeys = append(masterKeys, masterKey)
		}
		groups = append(groups, masterKeys)
	}

	return groups, nil
}

func storeForFormat(format DataFormat) (common.Store, error) {
	storesConfig := sopsconfig.NewStoresConfig()
	switch format {
	case FormatYAML:
		return common.StoreForFormat(formats.Yaml, storesConfig), nil
	case FormatJSON:
		return common.StoreForFormat(formats.Json, storesConfig), nil
	case FormatDotenv:
		return common.StoreForFormat(formats.Dotenv, storesConfig), nil
	case FormatINI:
		return common.StoreForFormat(formats.Ini, storesConfig), nil
	case FormatBinary:
		return common.StoreForFormat(formats.Binary, storesConfig), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
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
