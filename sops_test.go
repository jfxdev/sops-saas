package sops

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"filippo.io/age"
	getsops "github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/kms"
	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestNewCipher(t *testing.T) {
	cipher := NewCipher()
	if cipher == nil {
		t.Fatal("expected non-nil Cipher")
	}
}

func TestDecryptUnsupportedFormat(t *testing.T) {
	cipher := NewCipher()
	ctx := context.Background()

	_, err := cipher.Decrypt(ctx, []byte("some content"), "unsupported-format")
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	expectedErr := "unsupported format: unsupported-format"
	if err.Error() != expectedErr {
		t.Fatalf("expected error '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestEncryptUnsupportedFormat(t *testing.T) {
	cipher := NewCipher()
	ctx := context.Background()

	config := EncryptionConfig{
		Format: "unsupported-format",
	}

	_, err := cipher.Encrypt(ctx, []byte("some content"), config)
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	expectedErr := "unsupported format: unsupported-format"
	if err.Error() != expectedErr {
		t.Fatalf("expected error '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestReadEncryptionContexts(t *testing.T) {
	const keyARN = "arn:aws:kms:us-east-1:1234567890:key/abc-123"
	store, err := storeForFormat(FormatYAML)
	if err != nil {
		t.Fatalf("unexpected error creating store: %v", err)
	}

	content, err := store.EmitEncryptedFile(getsops.Tree{
		Branches: getsops.TreeBranches{
			getsops.TreeBranch{{Key: "secret", Value: "ENC[AES256_GCM,data:example]"}},
		},
		Metadata: getsops.Metadata{
			KeyGroups: []getsops.KeyGroup{
				{kms.NewMasterKeyFromArn(keyARN, kms.ParseKMSContext(map[string]interface{}{
					"environment": "production",
					"service":     "payments",
				}), "")},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error emitting SOPS content: %v", err)
	}

	contexts, err := NewCipher().ReadEncryptionContexts(content, FormatYAML)
	if err != nil {
		t.Fatalf("unexpected error reading contexts: %v", err)
	}

	expected := []EncryptionContext{{
		Platform: "aws/kms",
		KeyID:    keyARN,
		Context: map[string]string{
			"environment": "production",
			"service":     "payments",
		},
	}}
	if !reflect.DeepEqual(contexts, expected) {
		t.Fatalf("expected contexts %#v, got %#v", expected, contexts)
	}
}

func TestReadEncryptionContextsUnsupportedFormat(t *testing.T) {
	_, err := NewCipher().ReadEncryptionContexts([]byte("content"), "unsupported-format")
	if err == nil {
		t.Fatal("expected error for unsupported format, got nil")
	}
	if err.Error() != "unsupported format: unsupported-format" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEncryptDecryptWithKeyGroupsAndUpdateKeys(t *testing.T) {
	firstKey, firstIdentity := newAgeEncryptionKey(t)
	secondKey, secondIdentity := newAgeEncryptionKey(t)
	thirdKey, thirdIdentity := newAgeEncryptionKey(t)
	t.Setenv("SOPS_AGE_KEY", firstIdentity+"\n"+secondIdentity+"\n"+thirdIdentity)

	cipher := NewCipher()
	config := EncryptionConfig{
		Format: FormatYAML,
		KeyGroups: [][]entities.EncryptionKey{
			{firstKey},
			{secondKey},
		},
		ShamirThreshold: 2,
	}
	content := []byte("secret: example\n")
	encrypted, err := cipher.Encrypt(context.Background(), content, config)
	if err != nil {
		t.Fatalf("unexpected encryption error: %v", err)
	}

	store, err := storeForFormat(FormatYAML)
	if err != nil {
		t.Fatalf("unexpected store error: %v", err)
	}
	originalTree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		t.Fatalf("unexpected error loading encrypted content: %v", err)
	}
	if len(originalTree.Metadata.KeyGroups) != 2 || originalTree.Metadata.ShamirThreshold != 2 {
		t.Fatalf("expected two key groups with a threshold of two, got %#v", originalTree.Metadata)
	}

	plain, err := cipher.Decrypt(context.Background(), encrypted, FormatYAML)
	if err != nil {
		t.Fatalf("unexpected decryption error: %v", err)
	}
	if !bytes.Equal(plain, content) {
		t.Fatalf("expected plaintext %q, got %q", content, plain)
	}

	updated, err := cipher.UpdateKeys(context.Background(), encrypted, EncryptionConfig{
		Format:    FormatYAML,
		KeyGroups: [][]entities.EncryptionKey{{firstKey, thirdKey}},
	})
	if err != nil {
		t.Fatalf("unexpected update keys error: %v", err)
	}
	updatedTree, err := store.LoadEncryptedFile(updated)
	if err != nil {
		t.Fatalf("unexpected error loading updated content: %v", err)
	}
	if !reflect.DeepEqual(updatedTree.Branches, originalTree.Branches) {
		t.Fatal("UpdateKeys changed encrypted secret values")
	}
	if len(updatedTree.Metadata.KeyGroups) != 1 || len(updatedTree.Metadata.KeyGroups[0]) != 2 {
		t.Fatalf("expected one key group with two alternative keys, got %#v", updatedTree.Metadata.KeyGroups)
	}

	plain, err = cipher.Decrypt(context.Background(), updated, FormatYAML)
	if err != nil {
		t.Fatalf("unexpected decryption after key update: %v", err)
	}
	if !bytes.Equal(plain, content) {
		t.Fatalf("expected plaintext %q after key update, got %q", content, plain)
	}
}

func TestKeysAreOneGroupOfAlternatives(t *testing.T) {
	firstKey, _ := newAgeEncryptionKey(t)
	secondKey, _ := newAgeEncryptionKey(t)

	groups, err := buildKeyGroups(context.Background(), EncryptionConfig{
		Keys: []entities.EncryptionKey{firstKey, secondKey},
	})
	if err != nil {
		t.Fatalf("unexpected error building key groups: %v", err)
	}
	if len(groups) != 1 || len(groups[0]) != 2 {
		t.Fatalf("expected one group with two alternative keys, got %#v", groups)
	}
}

func TestEncryptDecryptAdditionalFormats(t *testing.T) {
	key, identity := newAgeEncryptionKey(t)
	t.Setenv("SOPS_AGE_KEY", identity)
	cipher := NewCipher()

	tests := []struct {
		name     string
		format   DataFormat
		content  []byte
		expected []byte
	}{
		{name: "dotenv", format: FormatDotenv, content: []byte("PASSWORD=secret\n"), expected: []byte("PASSWORD=secret\n")},
		{name: "ini", format: FormatINI, content: []byte("[app]\npassword=secret\n"), expected: []byte("[app]\npassword = secret\n")},
		{name: "binary", format: FormatBinary, content: []byte("\x00secret\xff"), expected: []byte("\x00secret\xff")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := cipher.Encrypt(context.Background(), tt.content, EncryptionConfig{
				Format: tt.format,
				Keys:   []entities.EncryptionKey{key},
			})
			if err != nil {
				t.Fatalf("unexpected encryption error: %v", err)
			}
			plain, err := cipher.Decrypt(context.Background(), encrypted, tt.format)
			if err != nil {
				t.Fatalf("unexpected decryption error: %v", err)
			}
			if !bytes.Equal(plain, tt.expected) {
				t.Fatalf("expected plaintext %q, got %q", tt.expected, plain)
			}
		})
	}
}

func TestEncryptionOptionsAreStoredInMetadata(t *testing.T) {
	key, identity := newAgeEncryptionKey(t)
	t.Setenv("SOPS_AGE_KEY", identity)
	cipher := NewCipher()
	config := EncryptionConfig{
		Format:                FormatYAML,
		Keys:                  []entities.EncryptionKey{key},
		EncryptedCommentRegex: "^encrypt$",
		MACOnlyEncrypted:      true,
	}

	encrypted, err := cipher.Encrypt(context.Background(), []byte("# encrypt\nsecret: value\n"), config)
	if err != nil {
		t.Fatalf("unexpected encryption error: %v", err)
	}
	store, err := storeForFormat(FormatYAML)
	if err != nil {
		t.Fatalf("unexpected store error: %v", err)
	}
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		t.Fatalf("unexpected error loading encrypted content: %v", err)
	}
	if tree.Metadata.EncryptedCommentRegex != config.EncryptedCommentRegex {
		t.Fatalf("expected encrypted comment regex %q, got %q", config.EncryptedCommentRegex, tree.Metadata.EncryptedCommentRegex)
	}
	if !tree.Metadata.MACOnlyEncrypted {
		t.Fatal("expected MACOnlyEncrypted to be stored in metadata")
	}
}

func newAgeEncryptionKey(t *testing.T) (entities.EncryptionKey, string) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("unexpected error generating age identity: %v", err)
	}
	return entities.EncryptionKey{
		Platform: "age",
		ID:       identity.Recipient().String(),
	}, identity.String()
}
