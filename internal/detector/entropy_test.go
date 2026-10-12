package detector

import "testing"

func TestEntropy_DetectsHighEntropyToken(t *testing.T) {
	e := NewEntropy()
	// Token acak 32 char tanpa kata-kunci di sekitarnya & di file non-.env.
	content := "the deploy value is 9fK2mZ7qTx4bV8nR1wL6cD3eH0sA5uJp here"
	fs := e.Detect("notes.txt", content)
	vals := found(content, fs)
	if len(vals) != 1 || vals[0] != "9fK2mZ7qTx4bV8nR1wL6cD3eH0sA5uJp" {
		t.Fatalf("harap mendeteksi token berentropi tinggi, dapat %v", vals)
	}
}

func TestEntropy_IgnoresNaturalLanguage(t *testing.T) {
	e := NewEntropy()
	// Kalimat biasa: entropi rendah per kata; tak boleh ada temuan.
	content := "this is a perfectly ordinary sentence without any secrets inside"
	if fs := e.Detect("doc.md", content); len(fs) != 0 {
		t.Fatalf("natural language tak boleh terdeteksi, dapat %v", found(content, fs))
	}
}

func TestEntropy_IgnoresUUID(t *testing.T) {
	e := NewEntropy()
	content := "id: 550e8400-e29b-41d4-a716-446655440000"
	if fs := e.Detect("config.yaml", content); len(fs) != 0 {
		t.Fatalf("UUID kanonik tak boleh terdeteksi, dapat %v", found(content, fs))
	}
}

func TestEntropy_IgnoresPureDigits(t *testing.T) {
	e := NewEntropy()
	content := "timestamp 17283947561827364509 end"
	if fs := e.Detect("log.txt", content); len(fs) != 0 {
		t.Fatalf("angka murni panjang tak boleh terdeteksi, dapat %v", found(content, fs))
	}
}

func TestEntropy_RespectsLengthBounds(t *testing.T) {
	e := NewEntropyWith(20, 128, 3.5)
	// String acak pendek (<20) tidak dinilai meski entropinya tinggi.
	content := "x9fK2mZ7qT"
	if fs := e.Detect("f.txt", content); len(fs) != 0 {
		t.Fatalf("kandidat < minLen harus dilewati, dapat %v", found(content, fs))
	}
}

func TestEntropy_OffPathWhenNotRegistered(t *testing.T) {
	// Registry tanpa Entropy tidak boleh menandai token acak (default aman).
	reg := NewRegistry(NewRegex(), NewDotEnv())
	content := "val 9fK2mZ7qTx4bV8nR1wL6cD3eH0sA5uJp"
	if fs := reg.Detect("notes.txt", content); len(fs) != 0 {
		t.Fatalf("tanpa entropy, token acak tak boleh terdeteksi di non-.env, dapat %v", found(content, fs))
	}

	// Dengan Entropy terdaftar, token yang sama tertangkap.
	reg2 := NewRegistry(NewRegex(), NewDotEnv(), NewEntropy())
	if fs := reg2.Detect("notes.txt", content); len(fs) == 0 {
		t.Fatal("dengan entropy, token acak harus terdeteksi")
	}
}

func TestShannonEntropy_Monotonic(t *testing.T) {
	// String seragam (entropi 0) < string campuran.
	if shannonEntropy("aaaaaaaa") != 0 {
		t.Fatalf("string seragam harus berentropi 0, dapat %v", shannonEntropy("aaaaaaaa"))
	}
	if shannonEntropy("abcdefgh") <= shannonEntropy("aaaaaaab") {
		t.Fatal("string lebih beragam harus berentropi lebih tinggi")
	}
}
