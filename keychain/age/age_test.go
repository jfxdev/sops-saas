package age

import (
	"context"
	"testing"

	ageidentity "filippo.io/age"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestNewKeyGroupSuccess(t *testing.T) {
	identity, err := ageidentity.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate age identity: %v", err)
	}

	ctx := context.Background()
	key := entities.EncryptionKey{ID: identity.Recipient().String()}

	result, err := NewKeyGroup(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil MasterKey")
	}
}

func TestNewKeyGroupInvalidRecipient(t *testing.T) {
	ctx := context.Background()
	key := entities.EncryptionKey{ID: "not-a-valid-age-recipient"}

	result, err := NewKeyGroup(ctx, key)
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
	if result != nil {
		t.Fatal("expected nil MasterKey for invalid recipient")
	}
}
