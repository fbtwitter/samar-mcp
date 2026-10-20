package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// resolveBinaryPath mengembalikan path absolut binary saat ini atau fallback "samar".
func resolveBinaryPath(binaryPath string) string {
	if binaryPath != "" {
		return binaryPath
	}
	exe, err := os.Executable()
	if err == nil {
		return exe
	}
	return "samar"
}

// updateMCPServerJSON membaca file konfigurasi JSON MCP, membuat file backup (.bak.<ts>),
// menambahkan/memperbarui objek mcpServers[serverName], dan menyimpannya kembali dengan format rapi.
func updateMCPServerJSON(configFile, serverName string, serverDef map[string]any) error {
	configDir := filepath.Dir(configFile)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("gagal membuat direktori konfigurasi %s: %w", configDir, err)
	}

	root := make(map[string]any)
	if data, err := os.ReadFile(configFile); err == nil {
		// Buat backup sebelum modifikasi
		bakFile := fmt.Sprintf("%s.bak.%d", configFile, time.Now().Unix())
		_ = os.WriteFile(bakFile, data, 0o600)

		if err := json.Unmarshal(data, &root); err != nil {
			return fmt.Errorf("format JSON rusak pada %s: %w", configFile, err)
		}
	}

	mcpServers, ok := root["mcpServers"].(map[string]any)
	if !ok {
		mcpServers = make(map[string]any)
		root["mcpServers"] = mcpServers
	}

	mcpServers[serverName] = serverDef

	output, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("gagal menyusun JSON konfigurasi: %w", err)
	}

	if err := os.WriteFile(configFile, append(output, '\n'), 0o600); err != nil {
		return fmt.Errorf("gagal menulis file konfigurasi %s: %w", configFile, err)
	}

	return nil
}
