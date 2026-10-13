package detector

import "testing"

func TestPii_DetectsEmail(t *testing.T) {
	p := NewPii()
	content := "kontak: john.doe@example.com untuk info"
	fs := p.Detect("notes.txt", content)
	vals := found(content, fs)
	if len(vals) != 1 || vals[0] != "john.doe@example.com" {
		t.Fatalf("harap mendeteksi email, dapat %v", vals)
	}
}

func TestPii_DetectsValidCreditCardLuhn(t *testing.T) {
	p := NewPii()
	// 4111 1111 1111 1111 adalah nomor uji Visa standar (lolos Luhn).
	content := "kartu 4111 1111 1111 1111 dipakai"
	fs := p.Detect("x.txt", content)
	if len(fs) == 0 {
		t.Fatal("kartu kredit valid (Luhn) harus terdeteksi")
	}
	// Pastikan detektornya memang credit_card.
	for _, f := range fs {
		if f.Detector == "pii:credit_card" {
			return
		}
	}
	t.Fatalf("harap temuan pii:credit_card, dapat %+v", fs)
}

func TestPii_RejectsInvalidLuhn(t *testing.T) {
	p := NewPii()
	// Deret 16 digit yang TIDAK lolos Luhn -> tak boleh ditandai credit_card.
	content := "angka 1234 5678 9012 3456 bukan kartu"
	for _, f := range p.Detect("x.txt", content) {
		if f.Detector == "pii:credit_card" {
			t.Fatalf("angka non-Luhn tak boleh ditandai sebagai kartu: %q", f.Value(content))
		}
	}
}

func TestPii_DetectsValidIBAN(t *testing.T) {
	p := NewPii()
	// GB82WEST12345698765432 adalah contoh IBAN kanonik (lolos mod-97).
	content := "transfer ke GB82WEST12345698765432 hari ini"
	found := false
	for _, f := range p.Detect("x.txt", content) {
		if f.Detector == "pii:iban" {
			found = true
		}
	}
	if !found {
		t.Fatal("IBAN valid harus terdeteksi")
	}
}

func TestPii_RejectsInvalidIBAN(t *testing.T) {
	p := NewPii()
	// Ubah satu digit cek supaya mod-97 gagal.
	content := "GB00WEST12345698765432"
	for _, f := range p.Detect("x.txt", content) {
		if f.Detector == "pii:iban" {
			t.Fatalf("IBAN tak valid tak boleh ditandai: %q", f.Value(content))
		}
	}
}

func TestPii_DetectsValidIPv4(t *testing.T) {
	p := NewPii()
	content := "server di 192.168.1.100 port 8080"
	found := false
	for _, f := range p.Detect("x.txt", content) {
		if f.Detector == "pii:ipv4" && f.Value(content) == "192.168.1.100" {
			found = true
		}
	}
	if !found {
		t.Fatal("IPv4 valid harus terdeteksi")
	}
}

func TestPii_RejectsInvalidIPv4(t *testing.T) {
	p := NewPii()
	// Oktet > 255 dan versi dengan leading zero tak boleh ditandai IP.
	for _, c := range []string{"999.1.1.1", "256.0.0.1", "01.02.03.04"} {
		for _, f := range p.Detect("x.txt", c) {
			if f.Detector == "pii:ipv4" {
				t.Fatalf("IP tak valid %q tak boleh ditandai (%q)", c, f.Value(c))
			}
		}
	}
}

func TestPii_NoFalsePositiveOnPlainText(t *testing.T) {
	p := NewPii()
	// Teks tanpa PII: versi semver, angka pendek, kata biasa.
	neutral := []string{
		"versi 1.2.3 dirilis",
		"timeout 30 detik",
		"halaman 42 dari 100",
	}
	for _, c := range neutral {
		if fs := p.Detect("doc.md", c); len(fs) != 0 {
			t.Errorf("false-positive PII pada %q: %v", c, found(c, fs))
		}
	}
}

func TestPii_RegistryIntegration(t *testing.T) {
	reg := NewRegistry(NewRegex(), NewPii())
	// Secret teknis (ghp_) + PII (email) harus sama-sama tertangkap.
	content := "token ghp_1234567890abcdefABCDEF1234567890abcd email a@b.co"
	fs := reg.Detect("x.txt", content)
	if len(fs) < 2 {
		t.Fatalf("registry harus gabung secret + PII, dapat %d: %v", len(fs), found(content, fs))
	}
	for i := 1; i < len(fs); i++ {
		if fs[i].Start < fs[i-1].End {
			t.Fatalf("rentang tumpang tindih setelah merge: %+v", fs)
		}
	}
}

func TestPii_OffWhenNotRegistered(t *testing.T) {
	// Tanpa Pii terdaftar, email polos tak boleh ditandai (default aman).
	reg := NewRegistry(NewRegex(), NewDotEnv())
	if fs := reg.Detect("notes.txt", "email a@b.co"); len(fs) != 0 {
		t.Fatalf("tanpa Pii, email tak boleh terdeteksi, dapat %v", found("email a@b.co", fs))
	}
}
