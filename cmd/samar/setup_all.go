package main

import (
	"fmt"
)

// runSetupAll menjalankan setup otomatis untuk seluruh AI client yang didukung secara berurutan.
func runSetupAll(binaryPath string) error {
	binaryPath = resolveBinaryPath(binaryPath)

	fmt.Println("==================================================")
	fmt.Println(" Samar MCP Server — Setup Komprehensif Multi-Agent")
	fmt.Println("==================================================")

	targets := []struct {
		name string
		fn   func(string, string) error
	}{
		{"Claude Code", runSetupClaudeCode},
		{"Kiro IDE", runSetupKiro},
		{"Cursor IDE", runSetupCursor},
		{"Google Antigravity (Gemini)", runSetupAntigravity},
	}

	successCount := 0
	for _, t := range targets {
		fmt.Printf("\n--- Menyiapkan %s ---\n", t.name)
		if err := t.fn("", binaryPath); err != nil {
			fmt.Printf("⚠ Gagal menyiapkan %s: %v\n", t.name, err)
		} else {
			successCount++
		}
	}

	fmt.Printf("\n✨ Selesai! %d/%d integrasi agent berhasil dikonfigurasi.\n", successCount, len(targets))
	return nil
}
