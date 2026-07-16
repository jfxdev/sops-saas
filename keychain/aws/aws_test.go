package aws

import (
	"context"
	"testing"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestNewKeyGroup(t *testing.T) {
	ctx := context.Background()
	key := entities.EncryptionKey{
		ID:   "arn:aws:kms:us-east-1:1234567890:key/abc",
		Role: "arn:aws:iam::1234567890:role/role",
	}

	result, err := NewKeyGroup(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil MasterKey")
	}
}
