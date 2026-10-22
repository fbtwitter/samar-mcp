package leakscan

import (
	"strings"
	"testing"

	"github.com/hanifalkauni/samar-mcp/internal/idgen"
	"github.com/hanifalkauni/samar-mcp/internal/vault"
)

func TestScan_FindsLeak(t *testing.T) {
	leaked := Scan("output berisi s3cr3t di tengah", []string{"s3cr3t", "tidakada"})
	if len(leaked) != 1 || leaked[0] != "s3cr3t" {
		t.Fatalf("harap menemukan 1 kebocoran, dapat %v", leaked)
	}
}

func TestClean_TrueWhenNoLeak(t *testing.T) {
	if !Clean("bersih tanpa secret", []string{"rahasia"}) {
		t.Fatal("harap Clean=true saat tak ada secret bocor")
	}
}

// fakeSource & fakeTok untuk unit test terisolasi SafetyNet.
type fakeSource struct{ secrets []string }

func (f fakeSource) Secrets() []string { return f.secrets }

type fakeTok struct{}

func (fakeTok) Tokenize(secret string) string { return "<TOK:" + secret[:3] + ">" }

func TestSafetyNet_ScrubPatchesLeak(t *testing.T) {
	sn := NewSafetyNet(fakeSource{secrets: []string{"supersecret"}}, fakeTok{})
	clean, patched := sn.Scrub("nilai bocor supersecret muncul")
	if patched != 1 {
		t.Fatalf("harap 1 kebocoran ditambal, dapat %d", patched)
	}
	if strings.Contains(clean, "supersecret") {
		t.Fatalf("secret masih bocor setelah scrub: %q", clean)
	}
}

func TestSafetyNet_NoLeakUnchanged(t *testing.T) {
	sn := NewSafetyNet(fakeSource{secrets: []string{"rahasia"}}, fakeTok{})
	in := "teks aman tanpa apa pun"
	clean, patched := sn.Scrub(in)
	if patched != 0 || clean != in {
		t.Fatalf("teks bersih tak boleh berubah, dapat patched=%d clean=%q", patched, clean)
	}
}

func TestSafetyNet_LongestSecretFirst(t *testing.T) {
	// "abc" adalah substring "abcdef"; harus menambal yang panjang dulu agar
	// tidak merusak penggantian.
	sn := NewSafetyNet(fakeSource{secrets: []string{"abc", "abcdef"}}, fakeTok{})
	clean, patched := sn.Scrub("lihat abcdef di sini")
	if strings.Contains(clean, "abcdef") {
		t.Fatalf("secret panjang masih bocor: %q", clean)
	}
	if patched == 0 {
		t.Fatal("harap ada penambalan")
	}
}

func TestSafetyNet_NilSafe(t *testing.T) {
	var sn *SafetyNet
	clean, patched := sn.Scrub("apa pun")
	if clean != "apa pun" || patched != 0 {
		t.Fatal("SafetyNet nil harus mengembalikan teks apa adanya")
	}
}

// Integrasi dengan vault NYATA: token hasil scrub harus bisa dikenali vault
// (deterministik, sama dengan token masking normal).
func TestSafetyNet_WithRealVault(t *testing.T) {
	v := vault.New(idgen.NewCryptoGen())
	secret := "AKIAIOSFODNN7EXAMPLE"
	// Tokenisasi awal (seolah lewat jalur masking normal).
	tok := v.Tokenize(secret)

	sn := NewSafetyNet(v, v)
	// Secret yang sama muncul mentah di output lain -> harus ditambal ke token
	// yang IDENTIK (determinisme reverse-map vault).
	clean, patched := sn.Scrub("echo " + secret)
	if patched != 1 {
		t.Fatalf("harap 1 penambalan, dapat %d", patched)
	}
	if !strings.Contains(clean, tok) {
		t.Fatalf("scrub harus memakai token vault yang sama (%s), dapat %q", tok, clean)
	}
	if strings.Contains(clean, secret) {
		t.Fatalf("secret masih bocor: %q", clean)
	}
}

func TestSafetyNet_ScrubPatchesBase64AndURLEncodedLeaks(t *testing.T) {
	v := vault.New(idgen.NewCryptoGen())
	secret := "myConfluencePat!@#123"
	tok := v.Tokenize(secret)

	sn := NewSafetyNet(v, v)
	// Base64 dari "myConfluencePat!@#123" adalah "bXlDb25mbHVlbmNlUGF0IUAjMTIz"
	b64Leak := "output base64: bXlDb25mbHVlbmNlUGF0IUAjMTIz"
	cleanB64, patchedB64 := sn.Scrub(b64Leak)
	if patchedB64 != 1 || !strings.Contains(cleanB64, tok) {
		t.Fatalf("Base64 secret tidak tertambal: patched=%d clean=%q", patchedB64, cleanB64)
	}

	// URL-encoded dari "myConfluencePat!@#123" adalah "myConfluencePat%21%40%23123"
	urlLeak := "https://example.com/?token=myConfluencePat%21%40%23123"
	cleanURL, patchedURL := sn.Scrub(urlLeak)
	if patchedURL != 1 || !strings.Contains(cleanURL, tok) {
		t.Fatalf("URL-encoded secret tidak tertambal: patched=%d clean=%q", patchedURL, cleanURL)
	}
}
