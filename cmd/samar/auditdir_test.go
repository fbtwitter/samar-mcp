package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectSlug(t *testing.T) {
	slug1 := projectSlug("/workspace/project-alpha")
	if !strings.HasPrefix(slug1, "project-alpha-") {
		t.Fatalf("expected prefix 'project-alpha-', got %q", slug1)
	}
	parts1 := strings.Split(slug1, "-")
	hash1 := parts1[len(parts1)-1]
	if len(hash1) != 8 {
		t.Fatalf("expected 8-char hash, got %q (len %d)", hash1, len(hash1))
	}

	// Distinct paths with identical base name must have different slugs
	slug2 := projectSlug("/other/path/project-alpha")
	if slug1 == slug2 {
		t.Fatalf("expected different slugs for different paths, got identical %q", slug1)
	}

	// Sanitization of strange characters
	slug3 := projectSlug("/path/to/weird!@#name$")
	if strings.ContainsAny(slug3, "!@#$") {
		t.Fatalf("expected slug to be sanitized, got %q", slug3)
	}

	// Empty string defaults to current working directory
	slugCur := projectSlug("")
	if slugCur == "" || !strings.Contains(slugCur, "-") {
		t.Fatalf("expected non-empty slug for empty cwd, got %q", slugCur)
	}
}

func TestResolveAuditDir(t *testing.T) {
	// 1. Explicit SAMAR_AUDIT_DIR override
	customDir := filepath.Join(t.TempDir(), "custom-audit")
	t.Setenv("SAMAR_AUDIT_DIR", customDir)
	t.Setenv("SAFEENV_AUDIT_DIR", "")
	if got := resolveAuditDir(""); got != customDir {
		t.Fatalf("expected customDir %q, got %q", customDir, got)
	}

	// 2. Fallback SAFEENV_AUDIT_DIR override
	t.Setenv("SAMAR_AUDIT_DIR", "")
	t.Setenv("SAFEENV_AUDIT_DIR", customDir)
	if got := resolveAuditDir(""); got != customDir {
		t.Fatalf("expected fallback customDir %q, got %q", customDir, got)
	}

	// 3. Default path based on user home dir
	t.Setenv("SAMAR_AUDIT_DIR", "")
	t.Setenv("SAFEENV_AUDIT_DIR", "")
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome)

	cwd := filepath.Join(fakeHome, "test-repo")
	got := resolveAuditDir(cwd)
	expectedPrefix := filepath.Join(fakeHome, ".samar", "audit")
	if !strings.HasPrefix(got, expectedPrefix) {
		t.Fatalf("expected path to start with %q, got %q", expectedPrefix, got)
	}
	if !strings.Contains(got, "test-repo-") {
		t.Fatalf("expected path to contain slug with 'test-repo-', got %q", got)
	}
}

func TestLazyFileWriter(t *testing.T) {
	tempDir := t.TempDir()
	targetDir := filepath.Join(tempDir, "audit-logs", "sub-repo")
	targetFile := "session-123.jsonl"

	w := newLazyFileWriter(targetDir, targetFile)

	// Before any write, targetDir and targetFile MUST NOT exist (lazy creation)
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Fatalf("expected targetDir to not exist yet, got err: %v", err)
	}
	fullPath := filepath.Join(targetDir, targetFile)
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Fatalf("expected targetFile to not exist yet, got err: %v", err)
	}

	// Calling Close() without writing must be a harmless no-op
	if err := w.Close(); err != nil {
		t.Fatalf("expected Close() on untouched writer to succeed, got %v", err)
	}
	if _, err := os.Stat(targetDir); !os.IsNotExist(err) {
		t.Fatalf("targetDir should still not exist after closing untouched writer")
	}

	// First write creates dir and file
	payload1 := []byte("{\"event\":\"test1\"}\n")
	n, err := w.Write(payload1)
	if err != nil {
		t.Fatalf("Write 1 failed: %v", err)
	}
	if n != len(payload1) {
		t.Fatalf("expected %d bytes written, got %d", len(payload1), n)
	}

	if _, err := os.Stat(fullPath); err != nil {
		t.Fatalf("expected file to exist after write, got %v", err)
	}

	// Second write appends
	payload2 := []byte("{\"event\":\"test2\"}\n")
	n2, err := w.Write(payload2)
	if err != nil {
		t.Fatalf("Write 2 failed: %v", err)
	}
	if n2 != len(payload2) {
		t.Fatalf("expected %d bytes written, got %d", len(payload2), n2)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("reading audit file failed: %v", err)
	}
	expectedContent := string(payload1) + string(payload2)
	if string(content) != expectedContent {
		t.Fatalf("unexpected content:\nwant:\n%s\ngot:\n%s", expectedContent, string(content))
	}
}
