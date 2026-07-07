package sops

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/jfxdev/sops-wrapper/keychain/entities"
)

func TestVaultIntegrationMocked(t *testing.T) {
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

	cipher := NewCipher()
	ctx := context.Background()

	config := EncryptionConfig{
		Format: FormatJSON,
		Keys: []entities.EncryptionKey{
			{
				Platform: "vault/kms",
				Parameters: map[string]string{
					"url":         ts.URL,
					"engine_path": "sops",
					"key_path":    "my-key",
				},
			},
		},
	}

	originalData := []byte(`{"secret":"super-confidential","public":"hello"}`)
	encrypted, err := cipher.Encrypt(ctx, originalData, config)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	decrypted, err := cipher.Decrypt(ctx, encrypted, FormatJSON)
	if err != nil {
		t.Fatalf("failed to decrypt: %v", err)
	}

	var originalMap, decryptedMap map[string]interface{}
	if err := json.Unmarshal(originalData, &originalMap); err != nil {
		t.Fatalf("failed to unmarshal original: %v", err)
	}
	if err := json.Unmarshal(decrypted, &decryptedMap); err != nil {
		t.Fatalf("failed to unmarshal decrypted: %v", err)
	}

	if !reflect.DeepEqual(originalMap, decryptedMap) {
		t.Errorf("decrypted data does not match original. Expected: %v, got: %v", originalMap, decryptedMap)
	}
}
