package azure

import (
	"context"
	"testing"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestNewKeyGroup(t *testing.T) {
	ctx := context.Background()
	key := entities.EncryptionKey{
		ID: "https://myvault.vault.azure.net/keys/my-key/1a2b3c",
	}

	result, err := NewKeyGroup(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil MasterKey")
	}
}

func TestNewKeyGroupInvalidURL(t *testing.T) {
	ctx := context.Background()
	key := entities.EncryptionKey{ID: "not-a-valid-azure-key-vault-url"}

	result, err := NewKeyGroup(ctx, key)
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	if result != nil {
		t.Fatal("expected nil MasterKey for invalid URL")
	}
}
