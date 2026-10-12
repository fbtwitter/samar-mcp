// entropy.go menambahkan detektor OPT-IN berbasis entropi Shannon untuk
// menangkap secret "telanjang" — string berentropi tinggi (token/kunci acak)
// yang TIDAK didahului kata-kunci (SECRET=, TOKEN=, dst.) sehingga lolos dari
// detektor Regex, dan berada di file non-.env sehingga lolos DotEnv.
//
// Detektor ini SENGAJA nonaktif secara default (diaktifkan via SAMAR_ENTROPY=1
// di composition root) karena entropi tinggi juga dimiliki nilai non-secret
// seperti hash commit, UUID, atau base64 data — sehingga berpotensi
// false-positive (over-masking). Pengguna yang memprioritaskan recall
// mengaktifkannya sebagai jaring tambahan.
//
// Strategi mengurangi false-positive:
//   - hanya memeriksa "kata" (dipisah whitespace/pemisah umum) dengan panjang
//     dalam rentang [minLen, maxLen];
//   - ambang entropi minimum (bit/char) yang relatif tinggi;
//   - melewati bentuk yang jelas BUKAN secret: UUID kanonik, angka murni,
//     dan kata yang mengandung spasi.
package detector

import (
	"math"
)

// Entropy adalah Detector berbasis entropi Shannon untuk token berentropi
// tinggi. Konservatif demi menekan false-positive.
type Entropy struct {
	minLen    int     // panjang minimum kandidat (karakter)
	maxLen    int     // panjang maksimum kandidat (hindari blob base64 besar)
	threshold float64 // ambang entropi Shannon minimum (bit per karakter)
}

// NewEntropy membuat detektor entropi dengan parameter default yang konservatif:
// panjang 20..128, ambang 3.5 bit/char. Nilai ini menangkap token acak (API key
// tanpa prefix, hex 40+, base64 pendek) sambil melewati kata biasa & UUID.
func NewEntropy() *Entropy {
	return &Entropy{minLen: 20, maxLen: 128, threshold: 3.5}
}

// NewEntropyWith memungkinkan penyetelan parameter (dipakai di test).
func NewEntropyWith(minLen, maxLen int, threshold float64) *Entropy {
	return &Entropy{minLen: minLen, maxLen: maxLen, threshold: threshold}
}

// Name memenuhi Detector.
func (e *Entropy) Name() string { return "entropy" }

// Detect memindai kandidat kata dan menandai yang berentropi tinggi. filename
// tidak dipakai (berlaku untuk semua konten); diterima demi kontrak Detector.
func (e *Entropy) Detect(_, content string) []Finding {
	var findings []Finding
	for _, span := range tokenize(content) {
		word := content[span.start:span.end]
		if !e.isCandidate(word) {
			continue
		}
		if shannonEntropy(word) >= e.threshold {
			findings = append(findings, Finding{
				Start:    span.start,
				End:      span.end,
				Detector: "entropy",
			})
		}
	}
	return findings
}

// isCandidate menyaring kata yang layak diuji entropinya.
func (e *Entropy) isCandidate(w string) bool {
	n := len(w)
	if n < e.minLen || n > e.maxLen {
		return false
	}
	if isAllDigits(w) {
		return false // angka panjang (ID, timestamp) bukan secret
	}
	if looksLikeUUID(w) {
		return false // UUID kanonik: entropi tinggi tapi umum non-secret
	}
	// Harus mengandung campuran yang wajar untuk sebuah token (minimal ada
	// huruf). Kata yang semuanya tanda baca/simbol dilewati.
	if !hasLetter(w) {
		return false
	}
	return true
}

// span adalah rentang byte sebuah kata di dalam konten.
type span struct{ start, end int }

// tokenize memecah konten menjadi "kata" berdasar pemisah umum (whitespace dan
// karakter yang lazim mengelilingi token: kutip, kurung, koma, dsb.) sambil
// mempertahankan offset byte. Pemisah dipilih agar token seperti
// "abc-def_123=" terpotong pada '=' sehingga nilai murni yang diuji.
func tokenize(content string) []span {
	var spans []span
	start := -1
	for i := 0; i < len(content); i++ {
		if isSep(content[i]) {
			if start >= 0 {
				spans = append(spans, span{start, i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		spans = append(spans, span{start, len(content)})
	}
	return spans
}

// isSep true untuk karakter pemisah token.
func isSep(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '`', '(', ')', '[', ']', '{', '}',
		',', ';', '=', '<', '>', '|':
		return true
	}
	return false
}

// shannonEntropy menghitung entropi Shannon (bit per karakter) dari s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func hasLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// looksLikeUUID mengenali UUID kanonik 8-4-4-4-12 heksadesimal.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
