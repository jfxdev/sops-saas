package aws

import (
	"context"
	"testing"

	"github.com/getsops/sops/v3/kms"
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

	masterKey, ok := result.(*kms.MasterKey)
	if !ok {
		t.Fatalf("expected AWS KMS MasterKey, got %T", result)
	}
	if masterKey.Role != key.Role {
		t.Fatalf("expected role %q, got %q", key.Role, masterKey.Role)
	}
}

func TestNewKeyGroupWithEncryptionContext(t *testing.T) {
	key := entities.EncryptionKey{
		ID:      "arn:aws:kms:us-east-1:1234567890:key/abc",
		Context: map[string]string{"environment": "production", "service": "payments"},
	}

	result, err := NewKeyGroup(context.Background(), key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	masterKey, ok := result.(*kms.MasterKey)
	if !ok {
		t.Fatalf("expected AWS KMS MasterKey, got %T", result)
	}
	if got := *masterKey.EncryptionContext["environment"]; got != "production" {
		t.Fatalf("expected environment context production, got %q", got)
	}
	if got := *masterKey.EncryptionContext["service"]; got != "payments" {
		t.Fatalf("expected service context payments, got %q", got)
	}
}
