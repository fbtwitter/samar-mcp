// Package leakscan menyediakan pemeriksaan sederhana untuk memastikan nilai
// rahasia yang diketahui tidak bocor ke sebuah teks (output tool, isi log).
// Dipakai oleh corpus adversarial (PRD §12) dan self-test redaksi audit (§10).
package leakscan

import (
	"encoding/base64"
	"net/url"
	"strings"
)

// Scan mengembalikan daftar secret (dari secrets) yang DITEMUKAN di dalam text.
// Hasil kosong berarti tidak ada kebocoran. Secret kosong diabaikan.
func Scan(text string, secrets []string) []string {
	var leaked []string
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(text, s) {
			leaked = append(leaked, s)
		}
	}
	return leaked
}

// Clean adalah helper boolean: true bila tidak ada secret yang bocor.
func Clean(text string, secrets []string) bool {
	return len(Scan(text, secrets)) == 0
}

// SecretSource menyediakan daftar secret yang diketahui untuk safety-net.
// Dipenuhi oleh *vault.Vault (lewat Secrets()). Dipersempit (Interface
// Segregation) agar safety-net tak bergantung pada seluruh API vault.
type SecretSource interface {
	Secrets() []string
}

// Tokenizer memetakan sebuah secret ke token placeholder-nya. Dipenuhi oleh
// *vault.Vault; token yang dihasilkan deterministik per-sesi (reverse-map).
type Tokenizer interface {
	Tokenize(secret string) string
}

// SafetyNet adalah lapisan verifikasi TERAKHIR pada jalur outbound-ke-LLM:
// sebelum sebuah hasil tool dikembalikan, ia memastikan tidak ada nilai secret
// yang diketahui vault muncul mentah di dalamnya. Ini "sabuk pengaman kedua" di
// atas masking normal — menangkap kasus di mana sebuah secret lolos detektor
// pada satu jalur namun identik dengan secret yang sudah ter-vault di jalur
// lain (mis. muncul dengan konteks berbeda di output perintah).
//
// Berbeda dengan sekadar menolak, SafetyNet MENAMBAL: secret yang bocor
// di-tokenisasi ulang memakai token vault yang sama, sehingga output tetap
// berguna namun aman. Perilaku ini idempoten dan tidak pernah membocorkan.
type SafetyNet struct {
	src SecretSource
	tok Tokenizer
}

// NewSafetyNet membuat safety-net dari sumber secret dan tokenizer vault.
func NewSafetyNet(src SecretSource, tok Tokenizer) *SafetyNet {
	return &SafetyNet{src: src, tok: tok}
}

// Scrub memindai text atas semua secret vault; bila ada yang bocor, menggantinya
// dengan token placeholder. Mengembalikan text bersih dan jumlah kebocoran yang
// ditambal (0 = sudah bersih). Secret diproses dari yang TERPANJANG dulu agar
// secret yang merupakan substring dari secret lain tidak merusak penggantian.
func (s *SafetyNet) Scrub(text string) (clean string, patched int) {
	if s == nil || s.src == nil || s.tok == nil {
		return text, 0
	}
	secrets := s.src.Secrets()
	// Urut dari terpanjang agar penggantian substring aman.
	sortByLenDesc(secrets)
	out := text
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		if strings.Contains(out, sec) {
			tok := s.tok.Tokenize(sec)
			n := strings.Count(out, sec)
			out = strings.ReplaceAll(out, sec, tok)
			patched += n
		}
		// Pertahanan terhadap kebocoran ter-encode (Base64 / URL-encoded) untuk secret
		// dengan panjang >= 6 karakter (menghindari false-positive pada string pendek).
		if len(sec) >= 6 {
			variants := encodedVariants(sec)
			for _, v := range variants {
				if v != "" && v != sec && strings.Contains(out, v) {
					tok := s.tok.Tokenize(sec)
					n := strings.Count(out, v)
					out = strings.ReplaceAll(out, v, tok)
					patched += n
				}
			}
		}
	}
	return out, patched
}

// encodedVariants menghasilkan representasi Base64 (Std & Raw) dan URL-encoded dari secret.
func encodedVariants(sec string) []string {
	b64Std := base64.StdEncoding.EncodeToString([]byte(sec))
	b64Raw := base64.RawStdEncoding.EncodeToString([]byte(sec))
	urlEnc := url.QueryEscape(sec)
	out := []string{b64Std}
	if b64Raw != b64Std {
		out = append(out, b64Raw)
	}
	if urlEnc != sec {
		out = append(out, urlEnc)
	}
	return out
}

// sortByLenDesc mengurutkan slice string menurun berdasarkan panjang (insertion
// sort sederhana; daftar secret per-sesi umumnya kecil).
func sortByLenDesc(ss []string) {
	for i := 1; i < len(ss); i++ {
		j := i
		for j > 0 && len(ss[j-1]) < len(ss[j]) {
			ss[j-1], ss[j] = ss[j], ss[j-1]
			j--
		}
	}
}
