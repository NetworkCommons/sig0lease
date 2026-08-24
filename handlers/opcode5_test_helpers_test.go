package handlers

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/NetworkCommons/sig0lease/logging"
)

func newTestHandler() *UpdateHandler {
	h := NewUpdateHandler()
	h.SetLogger(logging.NewLogger("debug"))
	return h
}

// createTestKeystore creates a temporary keystore directory with a valid server key
// so that Setup() can successfully load the upstream key.
func createTestKeystore(t *testing.T) (string, error) {
	// Use the pre-existing test key from the repository's keystore.
	// We need the key files in the top-level directory (as config points to server/ subdir).
	srcKeyFile := "../keystore/server/Kdev.zenr.io.+015+35317.key"
	srcPrivFile := "../keystore/server/Kdev.zenr.io.+015+35317.private"

	tmpDir := t.TempDir()

	// Copy the key file directly into the temp directory (not a subdirectory).
	if err := copyFile(srcKeyFile, filepath.Join(tmpDir, "Kdev.zenr.io.+015+35317.key")); err != nil {
		return "", err
	}
	// Copy the private key file.
	if err := copyFile(srcPrivFile, filepath.Join(tmpDir, "Kdev.zenr.io.+015+35317.private")); err != nil {
		return "", err
	}

	return tmpDir, nil
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}
