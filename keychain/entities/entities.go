package entities

type EncryptionKey struct {
	ID         string
	Platform   string
	Role       string
	Parameters map[string]string
	// Context is the AWS KMS encryption context. It is supported only when
	// Platform is "aws/kms".
	Context map[string]string
}
