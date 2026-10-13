// pii.go menambahkan detektor OPT-IN untuk Personally Identifiable Information
// (PII) — data pribadi yang bukan "secret teknis" (API key/password) sehingga
// tak tertangkap detektor Regex, tetapi tetap sensitif bila bocor ke LLM:
// email, nomor kartu kredit, IBAN, dan alamat IPv4.
//
// Detektor ini SENGAJA nonaktif secara default (diaktifkan via SAMAR_PII=1 di
// composition root) karena PII cenderung lebih sering memicu false-positive
// daripada secret berprefix (mis. deretan angka yang kebetulan lolos Luhn).
// Untuk menekan false-positive, kandidat berangka divalidasi secara struktural:
//   - kartu kredit: panjang 13..19 digit DAN lolos algoritma Luhn;
//   - IBAN: format negara + mod-97 == 1;
//   - IPv4: tiap oktet 0..255.
//
// Email memakai pola konservatif. Semua temuan memasking NILAI PII utuh.
package detector

import (
	"regexp"
	"strings"
)

// Pii adalah Detector untuk data pribadi (email, kartu kredit, IBAN, IPv4).
type Pii struct {
	emailRe *regexp.Regexp
	ccRe    *regexp.Regexp // kandidat deret angka (dengan spasi/strip opsional)
	ibanRe  *regexp.Regexp
	ipRe    *regexp.Regexp
}

// NewPii membuat detektor PII dengan pola default.
func NewPii() *Pii {
	must := regexp.MustCompile
	return &Pii{
		// Email konservatif: local-part + domain + TLD >= 2 huruf.
		emailRe: must(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
		// Kandidat kartu kredit: 13-19 digit, boleh dipisah spasi/strip per grup.
		// Validasi Luhn + penghitungan digit dilakukan di Detect.
		ccRe: must(`\b(?:\d[ -]?){13,19}\b`),
		// IBAN: 2 huruf negara + 2 digit cek + 11..30 alnum. Validasi mod-97 di Detect.
		ibanRe: must(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`),
		// IPv4 kandidat: empat grup 1-3 digit. Validasi rentang oktet di Detect.
		ipRe: must(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
	}
}

// Name memenuhi Detector.
func (p *Pii) Name() string { return "pii" }

// Detect memindai email, kartu kredit (Luhn), IBAN (mod-97), dan IPv4 (rentang
// oktet). filename tidak dipakai; diterima demi kontrak Detector.
func (p *Pii) Detect(_, content string) []Finding {
	var findings []Finding

	for _, m := range p.emailRe.FindAllStringIndex(content, -1) {
		findings = append(findings, Finding{Start: m[0], End: m[1], Detector: "pii:email"})
	}

	for _, m := range p.ccRe.FindAllStringIndex(content, -1) {
		cand := content[m[0]:m[1]]
		if digitsOnly := stripNonDigits(cand); isLuhnValid(digitsOnly) {
			findings = append(findings, Finding{Start: m[0], End: m[1], Detector: "pii:credit_card"})
		}
	}

	for _, m := range p.ibanRe.FindAllStringIndex(content, -1) {
		if isValidIBAN(content[m[0]:m[1]]) {
			findings = append(findings, Finding{Start: m[0], End: m[1], Detector: "pii:iban"})
		}
	}

	for _, m := range p.ipRe.FindAllStringIndex(content, -1) {
		if isValidIPv4(content[m[0]:m[1]]) {
			findings = append(findings, Finding{Start: m[0], End: m[1], Detector: "pii:ipv4"})
		}
	}

	return findings
}

// stripNonDigits mengembalikan hanya digit dari s (hapus spasi/strip).
func stripNonDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// isLuhnValid mengecek deret digit dengan algoritma Luhn. Panjang di luar
// 13..19 ditolak (menekan false-positive pada angka acak panjang).
func isLuhnValid(digits string) bool {
	n := len(digits)
	if n < 13 || n > 19 {
		return false
	}
	var sum int
	double := false
	for i := n - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// isValidIPv4 memverifikasi tiap oktet berada di 0..255. Menolak oktet
// berawalan nol ganda (mis. "01") agar tidak menandai versi/angka acak.
func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		if len(part) > 1 && part[0] == '0' {
			return false // leading zero: bukan representasi IP kanonik
		}
		val := 0
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return false
			}
			val = val*10 + int(part[i]-'0')
		}
		if val > 255 {
			return false
		}
	}
	return true
}

// isValidIBAN memvalidasi IBAN via mod-97 (ISO 13616/7064): pindahkan 4 karakter
// pertama ke belakang, ubah huruf jadi angka (A=10..Z=35), lalu mod 97 harus 1.
func isValidIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Pindahkan 4 karakter pertama ke akhir.
	rearranged := s[4:] + s[:4]
	// Hitung mod-97 secara inkremental untuk menghindari bilangan besar.
	var remainder int
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			remainder = (remainder*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			// Huruf -> dua digit (10..35), proses tiap digit.
			v := int(c-'A') + 10
			remainder = (remainder*10 + v/10) % 97
			remainder = (remainder*10 + v%10) % 97
		default:
			return false
		}
	}
	return remainder == 1
}
