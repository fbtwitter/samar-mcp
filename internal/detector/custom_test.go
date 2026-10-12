package detector

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePatternFile menulis isi pola ke file sementara dan mengembalikan path-nya.
func writePatternFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("tulis file pola: %v", err)
	}
	return p
}

func TestCustom_DetectsUserPattern(t *testing.T) {
	dir := t.TempDir()
	// Pola token internal fiktif: ACME- diikuti 10 digit.
	path := writePatternFile(t, dir, "patterns", "# token internal\nACME-[0-9]{10}\n")

	c := NewCustomRegex(time.Hour, path) // TTL besar: tak reload saat tes
	content := "deploy key = ACME-1234567890 selesai"
	fs := c.Detect("note.txt", content)
	vals := found(content, fs)
	if len(vals) != 1 || vals[0] != "ACME-1234567890" {
		t.Fatalf("harap mendeteksi token ACME, dapat %v", vals)
	}
}

func TestCustom_NamedSecretGroupMasksOnlyGroup(t *testing.T) {
	dir := t.TempDir()
	// Hanya grup "secret" (setelah "internal_key: ") yang dimasking.
	path := writePatternFile(t, dir, "patterns", `internal_key:\s*(?P<secret>[A-Z0-9]{8})`)

	c := NewCustomRegex(time.Hour, path)
	content := "internal_key: ABCD1234"
	fs := c.Detect("x.conf", content)
	vals := found(content, fs)
	if len(vals) != 1 || vals[0] != "ABCD1234" {
		t.Fatalf("harus mask grup 'secret' saja, dapat %v", vals)
	}
}

func TestCustom_IgnoresCommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := writePatternFile(t, dir, "patterns", "\n# ini komentar\n\nFOO-[0-9]+\n")

	c := NewCustomRegex(time.Hour, path)
	content := "nilai FOO-42 di sini"
	if fs := c.Detect("f.txt", content); len(fs) != 1 {
		t.Fatalf("harap 1 temuan dari pola valid, dapat %d", len(fs))
	}
}

func TestCustom_InvalidPatternSkippedNotFatal(t *testing.T) {
	dir := t.TempDir()
	// Baris pertama regex rusak (kurung tak tertutup); baris kedua valid.
	// Baris rusak harus dilewati tanpa mematikan baris valid.
	path := writePatternFile(t, dir, "patterns", "FOO-([0-9+\nBAR-[0-9]{3}\n")

	c := NewCustomRegex(time.Hour, path)
	content := "lihat BAR-123"
	fs := c.Detect("f.txt", content)
	vals := found(content, fs)
	if len(vals) != 1 || vals[0] != "BAR-123" {
		t.Fatalf("pola valid harus tetap aktif meski ada pola rusak, dapat %v", vals)
	}
}

func TestCustom_MissingFileIsNotError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "tidak-ada")

	c := NewCustomRegex(time.Hour, missing)
	if fs := c.Detect("f.txt", "apa pun ACME-1"); len(fs) != 0 {
		t.Fatalf("file hilang harus menghasilkan 0 pola, dapat %d", len(fs))
	}
}

func TestCustom_HotReloadPicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	path := writePatternFile(t, dir, "patterns", "AAA-[0-9]+\n")

	// TTL sangat kecil agar reload cepat terpicu pada Detect berikutnya.
	c := NewCustomRegex(10*time.Millisecond, path)

	content := "ada AAA-1 dan BBB-2"
	if len(c.Detect("f.txt", content)) != 1 {
		t.Fatalf("awal: harap deteksi pola AAA saja")
	}

	// Ubah file: tambah pola BBB. Pastikan mtime berubah.
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("AAA-[0-9]+\nBBB-[0-9]+\n"), 0o600); err != nil {
		t.Fatalf("tulis ulang: %v", err)
	}
	// Lewati TTL agar reload terjadi pada Detect berikutnya.
	time.Sleep(20 * time.Millisecond)

	if got := len(c.Detect("f.txt", content)); got != 2 {
		t.Fatalf("setelah reload: harap 2 temuan (AAA + BBB), dapat %d", got)
	}
}

func TestCustom_ReloadCallbackFires(t *testing.T) {
	dir := t.TempDir()
	path := writePatternFile(t, dir, "patterns", "AAA-[0-9]+\n")

	c := NewCustomRegex(10*time.Millisecond, path)

	fired := make(chan struct{}, 1)
	c.SetOnReload(func() { fired <- struct{}{} })

	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(path, []byte("AAA-[0-9]+\nCCC-[0-9]+\n"), 0o600); err != nil {
		t.Fatalf("tulis ulang: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	_ = c.Detect("f.txt", "trigger reload") // memicu maybeReload

	select {
	case <-fired:
		// ok: callback terpanggil saat snapshot ditukar
	case <-time.After(time.Second):
		t.Fatal("callback onReload tidak terpanggil setelah file berubah")
	}
}

func TestCustom_RegistryIntegration(t *testing.T) {
	dir := t.TempDir()
	path := writePatternFile(t, dir, "patterns", "ZZZ-[0-9]+\n")

	reg := NewRegistry(
		NewRegex(),
		NewCustomRegex(time.Hour, path),
	)
	// Konten dengan secret bawaan (ghp_) DAN pola kustom (ZZZ-).
	content := "token ghp_1234567890abcdefABCDEF1234567890abcd dan ZZZ-99"
	fs := reg.Detect("x.txt", content)
	if len(fs) < 2 {
		t.Fatalf("registry harus menggabung temuan bawaan + kustom, dapat %d: %v", len(fs), found(content, fs))
	}
	// Pastikan tak ada rentang tumpang tindih setelah merge.
	for i := 1; i < len(fs); i++ {
		if fs[i].Start < fs[i-1].End {
			t.Fatalf("rentang tumpang tindih setelah merge: %+v", fs)
		}
	}
}
