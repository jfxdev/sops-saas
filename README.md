# sops-wrapper

Integrated library wrapper for [**Mozilla SOPS**](https://github.com/mozilla/sops), ideal for run encryption/decryption on apps and web services, without need to install the official binary.

## Usage

### Simple Encryption Example

```go
package main

import (
	"context"
	"fmt"

	"github.com/jfxdev/sops-wrapper"
	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func main() {
    ctx := context.Background()
	cipher := sops.NewCipher()

	config := sops.EncryptionConfig{
		Format: sops.FormatYAML,
		Keys: []entities.EncryptionKey{
			{
				Platform: "aws/kms",
				ID:       "arn:aws:kms:us-east-1:1234567890:key/abc-123",
			},
		},
	}

	encrypted, err := cipher.Encrypt(ctx, []byte(`{"secret": "value"}`), config)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(encrypted))
}
```

### Supported Keychains

Here are examples of how to populate `EncryptionConfig.Keys` for each supported cloud provider.
`Keys` is a single key group: any key in it can decrypt the secret.

**1. AWS KMS**
```go
entities.EncryptionKey{
	Platform: "aws/kms",
	ID:       "arn:aws:kms:us-east-1:1234567890:key/abc-123",
	Role:     "", // Optional generic IAM Role ARN
	Context: map[string]string{
		"user": "api",
		"env":  "prod",
	}, // Optional AWS KMS Encryption Context
}
```

**2. Google Cloud KMS**
```go
entities.EncryptionKey{
    Platform: "gcp/kms",
    ID:       "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
}
```

**3. Azure Key Vault (AKV)**
```go
entities.EncryptionKey{
    Platform: "azure/kv",
    ID:       "https://myvault.vault.azure.net/keys/my-key/1a2b3c",
}
```

**4. HashiCorp Vault**
```go
entities.EncryptionKey{
    Platform: "vault/kms",
    Parameters: map[string]string{
        "url":         "https://vault.corp.local:8200",
        "engine_path": "sops",
        "key_path":    "my-encryption-key",
    },
}
```

## Key Rotation

Rotating keys involves decrypting existing documents and re-encrypting them with a new set of keys (generating a fresh DEK). To do this seamlessly:

```go
newConfig := sops.EncryptionConfig{
    Format: sops.FormatYAML,
    Keys: []entities.EncryptionKey{ /* New Keys here */ },
}

rotatedContent, err := cipher.Rotate(ctx, encryptedPayloadBytes, newConfig)
```

## Key Groups and Shamir Quorum

Use `KeyGroups` when more than one independent group must authorize access.
Keys within the same group are alternatives; with multiple groups, SOPS uses
Shamir secret sharing and requires the configured quorum.

```go
config := sops.EncryptionConfig{
	Format: sops.FormatYAML,
	KeyGroups: [][]entities.EncryptionKey{
		{operationsKMSKey, operationsAgeKey}, // either operations key
		{securityKMSKey},                     // security key
	},
	ShamirThreshold: 2, // both groups are required
}
```

`Keys` and `KeyGroups` cannot be used together.

## Update Keys Without Rotating Secret Values

`UpdateKeys` changes the SOPS master-key metadata and re-wraps the current
data key. The encrypted secret values and the data key are preserved. The
caller needs permission to decrypt the current data key and encrypt it for
every configured new key.

```go
updatedContent, err := cipher.UpdateKeys(ctx, encryptedPayloadBytes, sops.EncryptionConfig{
	Format:    sops.FormatYAML,
	KeyGroups: [][]entities.EncryptionKey{{newKMSKey, recoveryAgeKey}},
})
```

## Formats and Encryption Rules

The wrapper supports YAML, JSON, dotenv, INI and binary payloads through
`FormatYAML`, `FormatJSON`, `FormatDotenv`, `FormatINI` and `FormatBinary`.

Along with suffix and key-regex options, YAML payloads can use comment-based
rules and selective MAC coverage:

```go
config := sops.EncryptionConfig{
	Format:                sops.FormatYAML,
	Keys:                  []entities.EncryptionKey{ageKey},
	EncryptedCommentRegex: "^sops:encrypt$",
	MACOnlyEncrypted:      true,
}
```

`EncryptedCommentRegex` and `UnencryptedCommentRegex` are mutually exclusive
with the suffix and key-regex selection options. `MACOnlyEncrypted` leaves
unencrypted values outside the SOPS integrity MAC; enable it only when that
trade-off is intentional.

### Read AWS KMS Encryption Contexts

The AWS KMS encryption context is stored in the SOPS metadata and can be read
without decrypting the secret:

```go
contexts, err := cipher.ReadEncryptionContexts(encryptedPayloadBytes, sops.FormatYAML)
```

Each result contains the KMS key ARN and its context. This metadata is not
authenticated until the secret is decrypted, so authorization requirements
must be enforced in AWS KMS or IAM policies.
