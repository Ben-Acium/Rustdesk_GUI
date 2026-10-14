package web

import (
	"strings"
	"testing"
)

func testVault(t *testing.T) *vault {
	t.Helper()
	key, err := GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	v, err := newVault(key)
	if err != nil {
		t.Fatalf("newVault: %v", err)
	}
	return v
}

func TestVaultRoundTrip(t *testing.T) {
	v := testVault(t)
	const hash = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"

	box, err := v.seal("123456789", hash)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(string(box), hash) {
		t.Fatal("sealed value contains the plaintext")
	}

	got, err := v.open("123456789", box)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != hash {
		t.Fatalf("open = %q, want %q", got, hash)
	}
}

// A box is bound to its device, so a row copied into another device's record
// fails to open rather than handing that device a credential it never had.
func TestVaultRejectsWrongPeer(t *testing.T) {
	v := testVault(t)
	box, err := v.seal("123456789", "deadbeef")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := v.open("987654321", box); err == nil {
		t.Fatal("opened a box sealed for a different device")
	}
}

func TestVaultRejectsWrongKey(t *testing.T) {
	box, err := testVault(t).seal("123456789", "deadbeef")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := testVault(t).open("123456789", box); err == nil {
		t.Fatal("opened a box sealed under a different key")
	}
}

func TestVaultRejectsTampering(t *testing.T) {
	v := testVault(t)
	box, err := v.seal("123456789", "deadbeef")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	box[len(box)-1] ^= 0x01
	if _, err := v.open("123456789", box); err == nil {
		t.Fatal("opened a tampered box")
	}
}

// Truncation must be caught before slicing, not panic.
func TestVaultRejectsShortBox(t *testing.T) {
	v := testVault(t)
	if _, err := v.open("123456789", []byte{1, 2, 3}); err == nil {
		t.Fatal("opened a truncated box")
	}
}

// An unset key is a supported configuration, not a startup failure: the
// feature is simply off.
func TestVaultDisabledWithoutKey(t *testing.T) {
	v, err := newVault("")
	if err != nil {
		t.Fatalf("newVault(\"\"): %v", err)
	}
	if v.enabled() {
		t.Fatal("vault reports enabled with no key")
	}
	if _, err := v.seal("1", "x"); err != errVaultDisabled {
		t.Fatalf("seal error = %v, want errVaultDisabled", err)
	}
	if _, err := v.open("1", []byte("x")); err != errVaultDisabled {
		t.Fatalf("open error = %v, want errVaultDisabled", err)
	}
}

func TestVaultRejectsBadKeys(t *testing.T) {
	for _, key := range []string{"not base64!!", "c2hvcnQ="} {
		if _, err := newVault(key); err == nil {
			t.Fatalf("newVault(%q) accepted an invalid key", key)
		}
	}
}
