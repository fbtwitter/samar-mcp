// custom.go menambahkan detektor berbasis pola yang DIDEFINISIKAN PENGGUNA
// lewat file konfigurasi, tanpa perlu kompilasi ulang. Ini melengkapi Regex
// (pola bawaan) untuk secret berformat khusus/organisasi (mis. token internal
// perusahaan) yang tidak dikenali rule-set default.
//
// Format file (satu pola per baris):
//   - baris kosong & baris diawali '#' diabaikan (komentar)
//   - sisanya diperlakukan sebagai pola regex (sintaks RE2 Go)
//   - bila pola punya grup tangkap bernama "secret", hanya grup itu yang
//     dimasking; jika tidak, seluruh match (konsisten dengan regex.go)
//
// Lokasi default (di-wire di composition root): global (~/.samar/patterns) +
// per-project (./.samar/patterns). File yang tidak ada diabaikan (bukan error).
//
// Keamanan & ketahanan (meniru pola allowlist, PRD §13.5):
//   - hot lazy-reload berbasis mtime + TTL + atomic swap
//   - VALIDATE-BEFORE-SWAP: bila sebuah file gagal dibaca, pola lama file itu
//     dipertahankan (tidak dikosongkan). Baris regex yang gagal compile
//     dilewati tanpa menggagalkan baris lain, dan tidak pernah menukar set lama
//     dengan set kosong akibat error.
package detector

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// compiledRule menyimpan pola yang sudah dikompilasi beserta nama untuk audit.
type compiledRule struct {
	name string
	re   *regexp.Regexp
}

// customSource adalah satu file pola beserta mtime terakhir yang terbaca.
type customSource struct {
	path    string
	modTime time.Time
	rules   []compiledRule
}

// CustomRegex adalah Detector yang memuat pola dari file konfigurasi pengguna
// dan memuat ulang secara lazy saat file berubah. Aman untuk konkurensi:
// snapshot aturan aktif disimpan di atomic.Value dan di-swap utuh saat reload.
type CustomRegex struct {
	mu       sync.Mutex
	sources  []*customSource
	ttl      time.Duration
	lastScan time.Time
	snapshot atomic.Value // []compiledRule
	onReload func()       // opsional: dipanggil setelah snapshot di-swap (audit)
}

// NewCustomRegex membuat detektor pola kustom dari daftar path. Path kosong
// diabaikan. File yang belum ada tetap dipantau: begitu dibuat & TTL lewat,
// polanya ikut aktif (hot-reload). ttl mengatur frekuensi cek mtime.
func NewCustomRegex(ttl time.Duration, paths ...string) *CustomRegex {
	c := &CustomRegex{ttl: ttl}
	for _, p := range paths {
		if p != "" {
			c.sources = append(c.sources, &customSource{path: p})
		}
	}
	c.snapshot.Store([]compiledRule{})
	c.reload(true)
	return c
}

// SetOnReload mendaftarkan callback yang dipanggil setiap kali reload benar-benar
// menukar snapshot (file pola berubah). Dipakai untuk audit config_reload.
func (c *CustomRegex) SetOnReload(fn func()) {
	c.mu.Lock()
	c.onReload = fn
	c.mu.Unlock()
}

// Name memenuhi Detector; format "custom:<rule>" ditetapkan per-temuan di Detect.
func (c *CustomRegex) Name() string { return "custom" }

// Detect menjalankan semua pola kustom aktif dan mengembalikan rentang byte yang
// cocok. Memicu lazy reload bila TTL terlampaui. filename tidak dipakai (pola
// kustom berlaku untuk semua konten), tetap diterima demi kontrak Detector.
func (c *CustomRegex) Detect(_, content string) []Finding {
	c.maybeReload()
	rules, _ := c.snapshot.Load().([]compiledRule)

	var findings []Finding
	for _, ru := range rules {
		idx := ru.re.SubexpIndex("secret")
		for _, m := range ru.re.FindAllStringSubmatchIndex(content, -1) {
			start, end := m[0], m[1]
			if idx > 0 && m[2*idx] >= 0 { // ada grup "secret"
				start, end = m[2*idx], m[2*idx+1]
			}
			if end > start {
				findings = append(findings, Finding{
					Start:    start,
					End:      end,
					Detector: "custom:" + ru.name,
				})
			}
		}
	}
	return findings
}

// maybeReload memeriksa TTL; murah bila belum waktunya.
func (c *CustomRegex) maybeReload() {
	c.mu.Lock()
	due := time.Since(c.lastScan) >= c.ttl
	c.mu.Unlock()
	if due {
		c.reload(false)
	}
}

// reload membaca ulang source yang berubah dan menukar snapshot secara atomik.
// Validate-before-swap: file yang gagal dibaca/parse mempertahankan pola lama.
// force=true membaca semua tanpa cek mtime (dipakai saat konstruksi).
func (c *CustomRegex) reload(force bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	changed := false
	for _, s := range c.sources {
		info, err := os.Stat(s.path)
		if err != nil {
			continue // file tidak ada / tak terbaca: pertahankan pola lama
		}
		if !force && info.ModTime().Equal(s.modTime) {
			continue
		}
		rules, perr := parsePatternFile(s.path)
		if perr != nil {
			continue // baca gagal: fail-safe, jangan ganti
		}
		s.rules = rules
		s.modTime = info.ModTime()
		changed = true
	}
	c.lastScan = time.Now()

	if changed || force {
		c.snapshot.Store(c.resolve())
	}
	if changed && !force && c.onReload != nil {
		c.onReload()
	}
}

// resolve menggabungkan aturan dari semua source menjadi satu daftar.
func (c *CustomRegex) resolve() []compiledRule {
	var all []compiledRule
	for _, s := range c.sources {
		all = append(all, s.rules...)
	}
	return all
}

// parsePatternFile membaca pola satu-per-baris; '#' = komentar, baris kosong
// diabaikan. Setiap pola dikompilasi; pola yang gagal compile DILEWATI (tidak
// menggagalkan file) agar satu typo tidak mematikan seluruh deteksi kustom.
// Nama rule diturunkan dari nomor baris agar unik di audit (mis. "line7").
func parsePatternFile(path string) ([]compiledRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []compiledRule
	sc := bufio.NewScanner(f)
	// Pola bisa panjang; naikkan batas buffer dari default 64KB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		re, cerr := regexp.Compile(line)
		if cerr != nil {
			// Pola rusak dilewati; baris lain tetap diproses (fail-safe).
			continue
		}
		rules = append(rules, compiledRule{name: lineName(lineNo), re: re})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

// lineName menghasilkan nama rule stabil berbasis nomor baris, mis. "line12".
func lineName(n int) string {
	return "line" + itoa(n)
}

// itoa adalah konversi int->string minimal tanpa impor strconv demi menjaga
// dependency paket tetap kecil (konsisten dengan gaya file detektor lain).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
