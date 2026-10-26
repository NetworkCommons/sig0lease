// Package sealedfile keeps a JSON document in a file that is written atomically and carries
// the SHA-256 of the document: the proxy's lease store snapshot and sig0lease-agent's state.
// These files are not meant to be edited by hand, and Read enforces that: it accepts only a
// file identical, byte for byte, to what Write makes of the document it holds, so any edit --
// to a value, to the whitespace, or to the layout -- is refused. It is a checksum, not a
// signature: the keys a program could sign with sit on the same host as the file, so a
// signature would make the check no harder to get past on purpose.
package sealedfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// file is the layout Write writes: the document's JSON, and the SHA-256 of exactly those
// bytes. The document's key is "snapshot", the name the lease store's files have always used.
type file struct {
	SHA256   string          `json:"sha256"`
	Document json.RawMessage `json:"snapshot"`
}

// fileBytes is the file Write writes for body, the document's JSON. It is assembled here
// rather than by marshaling a file, because encoding/json re-indents a RawMessage: this way
// the document's bytes in the file are exactly the bytes hashed.
func fileBytes(body []byte) []byte {
	return fmt.Appendf(nil, "{\n  \"sha256\": \"%x\",\n  \"snapshot\": %s\n}\n", sha256.Sum256(body), body)
}

// Write stores v, marshaled to JSON, at path, atomically (see writeAtomic).
func Write(path string, v any) error {
	// Indented one level deeper, as the value of file's "snapshot" key.
	body, err := json.MarshalIndent(v, "  ", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	return writeAtomic(path, fileBytes(body))
}

// Read unmarshals the document stored at path into v. A file that is not, byte for byte, what
// Write wrote is an error. A missing file is an error wrapping fs.ErrNotExist, so a caller can
// tell "nothing saved yet" from a broken file with errors.Is.
func Read(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	if len(f.Document) == 0 || f.SHA256 == "" {
		return fmt.Errorf("%s has no sha256/snapshot pair -- it was not written by this version", path)
	}
	if !bytes.Equal(data, fileBytes(f.Document)) {
		return fmt.Errorf("%s is not as it was written (its SHA-256 or layout doesn't match): it must not be edited by hand", path)
	}
	if err := json.Unmarshal(f.Document, v); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return nil
}

// writeAtomic writes data to path so that path always holds either its previous content or
// all of data, never part of it: a crash mid-save would otherwise leave a file that fails
// Read's checksum. data goes to a new temporary file (mode 0600) in path's directory -- the
// same filesystem, so the rename is atomic -- which is synced and then renamed over path; the
// directory is synced last so the rename itself survives a power loss. A unique temporary name
// means two saves to the same path can't interleave into one torn file. On failure the
// temporary file is removed.
func writeAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			return
		}
		if rmErr := os.Remove(tmp.Name()); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, rmErr)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err = tmp.Sync(); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename in dir durable. Windows has no directory sync -- it can't open a
// directory for it -- so there the rename is atomic but may not survive a power loss.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
