package vault

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestNewKeyGroup(t *testing.T) {
	ctx := context.Background()
	key := entities.EncryptionKey{
		Parameters: map[string]string{
			"url":         "https://vault.corp.local:8200",
			"engine_path": "sops",
			"key_path":    "my-key",
		},
	}

	result, err := NewKeyGroup(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil MasterKey")
	}
}

func TestVaultMasterKeyEncryptDecrypt(t *testing.T) {
	// Start local mock HTTP server simulating Vault Transit Secret Engine
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if r.Method != http.MethodPut {
			http.Error(w, "invalid method", http.StatusMethodNotAllowed)
			return
		}

		switch r.URL.Path {
		case "/v1/sops/encrypt/my-key":
			var req struct {
				Plaintext string `json:"plaintext"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Just prepend "vault:v1:" to the base64 plaintext to simulate ciphertext
			resp := map[string]interface{}{
				"data": map[string]string{
					"ciphertext": "vault:v1:" + req.Plaintext,
				},
			}
			respBytes, _ := json.Marshal(resp)
			w.Write(respBytes)

		case "/v1/sops/decrypt/my-key":
			var req struct {
				Ciphertext string `json:"ciphertext"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Remove the prefix "vault:v1:" to get back the base64 plaintext
			plaintext := req.Ciphertext
			if len(plaintext) > 9 && plaintext[:9] == "vault:v1:" {
				plaintext = plaintext[9:]
			}
			resp := map[string]interface{}{
				"data": map[string]string{
					"plaintext": plaintext,
				},
			}
			respBytes, _ := json.Marshal(resp)
			w.Write(respBytes)

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// Set VAULT_TOKEN environment variable required by the hcvault library
	os.Setenv("VAULT_TOKEN", "myroot")
	defer os.Unsetenv("VAULT_TOKEN")

	ctx := context.Background()
	key := entities.EncryptionKey{
		Parameters: map[string]string{
			"url":         ts.URL,
			"engine_path": "sops",
			"key_path":    "my-key",
		},
	}

	masterKey, err := NewKeyGroup(ctx, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if masterKey == nil {
		t.Fatal("expected non-nil MasterKey")
	}

	originalDataKey := []byte("some-random-generated-data-key-bytes")
	
	// Test Encrypt
	err = masterKey.Encrypt(originalDataKey)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	encryptedKeyBytes := masterKey.EncryptedDataKey()
	if len(encryptedKeyBytes) == 0 {
		t.Fatal("expected non-empty encrypted data key")
	}

	// Test Decrypt
	decryptedDataKey, err := masterKey.Decrypt()
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	if string(decryptedDataKey) != string(originalDataKey) {
		t.Errorf("decrypted data key does not match original. Expected: %s, got: %s", string(originalDataKey), string(decryptedDataKey))
	}
}
