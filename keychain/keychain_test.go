package keychain

import (
	"testing"

	"github.com/jfxdev/sops-wrapper/keychain/age"
	"github.com/jfxdev/sops-wrapper/keychain/aws"
	"github.com/jfxdev/sops-wrapper/keychain/azure"
	"github.com/jfxdev/sops-wrapper/keychain/gcp"
	"github.com/jfxdev/sops-wrapper/keychain/vault"
)

func TestKeyGroupSuccess(t *testing.T) {
	aliases := []string{
		age.Alias,
		aws.Alias,
		azure.Alias,
		gcp.Alias,
		vault.Alias,
	}

	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			fn, err := KeyGroup(alias)
			if err != nil {
				t.Fatalf("expected no error for alias %s, got %v", alias, err)
			}
			if fn == nil {
				t.Fatalf("expected valid KeyGroupFunc for alias %s", alias)
			}
		})
	}
}

func TestKeyGroupNotFound(t *testing.T) {
	alias := "invalid/alias"
	fn, err := KeyGroup(alias)
	if err == nil {
		t.Fatal("expected error for invalid alias")
	}
	if fn != nil {
		t.Fatal("expected nil KeyGroupFunc for invalid alias")
	}
}
