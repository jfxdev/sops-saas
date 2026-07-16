package gcp

import (
	"context"
	"testing"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestNewKeyGroup(t *testing.T) {
	ctx := context.Background()
	key := entities.EncryptionKey{
		ID: "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
	}

	result, err := NewKeyGroup(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil MasterKey")
	}
}
