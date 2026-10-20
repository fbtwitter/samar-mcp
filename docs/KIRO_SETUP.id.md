# Panduan Setup Samar di Kiro IDE

[English](./KIRO_SETUP.md) | **Bahasa Indonesia**

Panduan langkah demi langkah untuk memasang Samar MCP Server di **Kiro IDE**
sehingga kredensial benar-benar terlindungi. Panduan umum lintas-client ada di
[`CLIENT_CONFIG.md`](./CLIENT_CONFIG.md); dokumen ini khusus Kiro dan konkret.

> **Ingat prinsipnya:** mendaftarkan server MCP saja **tidak cukup**. Samar
> hanya memasking I/O yang **melewati tool-nya**. Selama tool bawaan Kiro
> (`fs_read`/`fs_write`) masih bisa membaca file sensitif langsung, secret
> bocor tanpa masking. Langkah **2** (deny rule) adalah yang membuat
> perlindungan ini nyata — bukan opsional.

---

## Ikhtisar: 3 langkah

| # | Langkah | Siapa | Status |
| :-- | :-- | :-- | :-- |
| 1 | Daftarkan server Samar di `mcp.json` | Bisa via agen | Wajib |
| 2 | Buat `permissions.yaml` (deny tool bawaan untuk file sensitif) | **Manual (kamu)** | **Wajib** |
| 3 | Siapkan egress allowlist | Bisa via agen | Opsional (untuk outbound) |

Langkah 2 harus manual: Kiro sengaja **melarang agen AI menulis file
permission-nya sendiri** (`~/.kiro/settings/` dan `~/.kiro/workspace-roots/`).
Ini guardrail yang benar — agen tidak boleh mengubah batas izinnya sendiri.

> ⚡ **Cara Tercepat:** Jalankan `samar setup kiro` dari terminal Anda (di luar agen) untuk mengotomasi Langkah 1 (`mcp.json`), Langkah 2 (`permissions.yaml`), dan instruksi agen dalam satu langkah!

---

## Prasyarat

Siapkan binary `samar`. Pilih salah satu:

- **Pakai rilis Windows yang sudah ada:**
  ```powershell
  Copy-Item .\dist\safeenv-windows-amd64.exe .\dist\samar.exe -Force
  .\dist\samar.exe --version   # harus mencetak versi, mis. "samar 1.2.1"
  ```
- **Build dari source:**
  ```powershell
  go build -o dist\samar.exe .\cmd\samar
  ```

Catat **path absolut** binary-nya (mis. `C:\MyProject\safeenv-mcp-server\dist\samar.exe`).

---

## Langkah 1 — Daftarkan server MCP

Pilih scope:

- **Workspace** (hanya aktif saat project ini dibuka):
  `.<project>\.kiro\settings\mcp.json`
- **User/global** (aktif di semua workspace):
  `~\.kiro\settings\mcp.json`

Isi (ganti path `command` dengan path absolut binary-mu, pakai `\\` di JSON):

```json
{
  "mcpServers": {
    "samar": {
      "command": "C:\\MyProject\\safeenv-mcp-server\\dist\\samar.exe",
      "args": [],
      "env": {
        "SAMAR_STRICT_ALLOWLIST": "0"
      },
      "disabled": false,
      "autoApprove": ["samar_read_file", "samar_get_env"]
    }
  }
}
```

> Env expansion Kiro memakai sintaks `${VAR}` (bukan `${env:VAR}`).
> `autoApprove` hanya untuk tool **baca** (aman); tool tulis/exec tetap minta
> konfirmasi. `disabledTools` di config MCP **tidak** mematikan tool bawaan
> Kiro — itu urusan Langkah 2.

Setelah menyimpan, reconnect server dari panel **MCP Server** di Kiro (atau
restart Kiro). Harusnya `samar` tersambung dengan 4 tool:
`samar_read_file`, `samar_get_env`, `samar_write_file`, `samar_execute_command`.

---

## Langkah 2 — Deny tool bawaan untuk file sensitif (WAJIB, manual)

Buat file `permissions.yaml`. Lokasi (keduanya **di luar** repo, per-user):

- **Global (disarankan, lindungi semua project):**
  `C:\Users\<kamu>\.kiro\settings\permissions.yaml`
- **Workspace saja:**
  `C:\Users\<kamu>\.kiro\workspace-roots\<hash>\permissions.yaml`
  (Kiro membuat `<hash>` otomatis; cara termudah lihat "Alternatif via UI" di bawah.)

Isi file:

```yaml
# Paksa I/O file sensitif lewat tool Samar dengan men-deny fs_read/fs_write
# bawaan Kiro pada path yang mengandung secret.
# Evaluasi deny-overrides: deny selalu menang atas allow/ask.
rules:
  - capability: fs_read
    effect: deny
    match:
      - "**/.env"
      - "**/.env.*"
      - "**/*.pem"
      - "**/*.key"
      - "secrets/**"

  - capability: fs_write
    effect: deny
    match:
      - "**/.env"
      - "**/.env.*"
      - "**/*.pem"
      - "**/*.key"
      - "secrets/**"
```

Cara membuatnya (lewat terminal di LUAR agen Kiro, atau editor biasa):

```powershell
notepad "$env:USERPROFILE\.kiro\settings\permissions.yaml"
```

**Catatan glob:** gunakan prefiks `**/` agar cocok di kedalaman folder mana pun.
Pola seperti `*.env` hanya cocok dalam satu komponen path. `permissions.yaml`
**menambah** default Kiro, bukan menggantinya.

### Alternatif via UI (paling mudah untuk scope workspace)

Saat agen mencoba membaca sebuah `.env`, Kiro memunculkan prompt izin. Pilih
**Deny → This workspace**. Kiro akan menuliskan rule-nya ke
`workspace-roots/<hash>/permissions.yaml` untukmu — tanpa cari `<hash>` manual.

### Isolasi penuh (opsional, agresif)

Kalau agen memang hanya boleh ber-I/O lewat Samar, tambahkan deny `shell`
bawaan dan arahkan eksekusi ke `samar_execute_command`. Hati-hati: ini bisa
melumpuhkan kemampuan agen menjalankan perintah biasa.

---

## Langkah 3 — Egress allowlist (outbound)

`samar_execute_command` memblokir pengiriman secret ter-unmask ke host yang
tidak ada di allowlist (fail-closed). Satu host per baris, `#` = komentar,
hot-reload tiap ~5 detik tanpa restart.

- **Global:** `~\.samar\allowlist` (fallback: `~\.safeenv\allowlist`)
- **Per-project:** `.\.samar\allowlist` (fallback: `.\.safeenv\allowlist`)

Contoh `.\.samar\allowlist`:

```text
# Hanya host di sini yang boleh menerima secret via samar_execute_command.
# api.internal.example.com
# registry.corp.local
```

Mode resolusi: **union** (default, `global ∪ project`) atau **strict**
(`SAMAR_STRICT_ALLOWLIST=1`, `global ∩ project`).

---

## Verifikasi

1. Reconnect/restart; pastikan `samar` muncul dengan 4 tool, dan peringatan
   keamanan tercetak di stderr saat server start.
2. Buat `.env` uji berisi secret palsu, mis. `API_KEY=sk-test-123456`.
3. Minta agen membaca file itu **lewat Samar** → output harus
   `__SAMAR_SECRET_...__`, bukan nilai asli.
4. Minta agen membaca file yang sama **secara normal** (tool bawaan) → harus
   **DITOLAK** oleh deny rule. Kalau nilai asli muncul, Langkah 2 belum aktif.

Uji bypass yang lebih menyeluruh: lihat [`BYPASS_TEST.md`](./BYPASS_TEST.md).

---

## Troubleshooting

| Gejala | Penyebab & solusi |
| :-- | :-- |
| `samar` tak muncul di daftar tool | Path `command` salah / binary tak ada. Cek dengan `samar.exe --version`. Reconnect server. |
| AI masih baca secret mentah dari `.env` | Langkah 2 belum ada / glob tak cocok. Pastikan `permissions.yaml` ada di `~/.kiro/settings/` dan pakai prefiks `**/`. |
| Agen tak bisa menulis `permissions.yaml` | Memang disengaja — Kiro melarang agen menulis file izinnya. Buat manual lewat editor/terminal biasa. |
| Perintah jaringan diblokir terus | Host tujuan belum ada di allowlist. Tambahkan ke `.samar/allowlist`. |
| Konfirmasi human-in-the-loop tak muncul | Set `SAMAR_REQUIRE_CONFIRM=elicit` (butuh client yang mendukung MCP elicitation). |
