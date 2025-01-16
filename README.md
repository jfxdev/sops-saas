# sops-saas

Integrated library wrapper for [**Mozilla SOPS**](https://github.com/mozilla/sops), ideal for run encryption/decryption on apps and web services, without need to install the official binary.
## Usage

```go
import "github.com/jfxdev/sops-saas"
```

```go

cypher := sops.NewCypher()

keys := []entities.EncryptionKey{
    {
        ID:       "arn:aws:kms:us-east-2:XXXXXXXXXXXX:key/YYYYYYYY-YYYY-YYYYY-YYYY-YYYYYYYYYYY",
        Platform: "aws/kms",
        Role:     "arn:aws:iam::XXXXXXXXXXXX:role/your-aws-role",
        Context:  map[string]string{"context": "sops"},
    }
x}

result, err := cypher.Encrypt(body, sops.EncryptionConfig{
		Keys:              keys,
		UnencryptedSuffix: "",
		EncryptedSuffix:   "",
		UnencryptedRegex:  "",
		EncryptedRegex:    "^(data)$",
		ShamirThreshold:   3,
		Format:            "yaml",
})

```