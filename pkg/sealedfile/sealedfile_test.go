package sealedfile

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

type doc struct {
	Names map[string]string `json:"names"`
}

func TestWriteRead_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := doc{Names: map[string]string{"laptop": "laptop-2"}}
	if err := Write(path, want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var got doc
	if err := Read(path, &got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Names["laptop"] != "laptop-2" || len(got.Names) != 1 {
		t.Fatalf("Read = %+v, want %+v", got, want)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the file in its directory, no temporary file left, got %d entries", len(entries))
	}
}

// A missing file is reported as such, so a caller can start from nothing.
func TestRead_MissingFileIsNotExist(t *testing.T) {
	var got doc
	err := Read(filepath.Join(t.TempDir(), "none.json"), &got)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read of a missing file = %v, want an error wrapping fs.ErrNotExist", err)
	}
}

// Any byte Write did not write is refused, and none of those refusals reads as a missing file.
func TestRead_RefusesEdits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Write(path, doc{Names: map[string]string{"laptop": "laptop-2"}}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	edits := map[string][]byte{
		"value changed":     bytes.Replace(saved, []byte("laptop-2"), []byte("laptop-3"), 1),
		"whitespace added":  bytes.Replace(saved, []byte(`"names": `), []byte(`"names":  `), 1),
		"trailing data":     append(append([]byte{}, saved...), "{}"...),
		"no checksum":       []byte(`{"names": {"laptop": "laptop-2"}}`),
		"not JSON":          []byte("laptop=laptop-2"),
		"checksum replaced": append(append(append([]byte{}, saved[:15]...), "00000000"...), saved[23:]...),
	}
	for desc, data := range edits {
		if bytes.Equal(data, saved) {
			t.Fatalf("%s: the edit did not change the file", desc)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("%s: write: %v", desc, err)
		}
		var got doc
		err := Read(path, &got)
		if err == nil {
			t.Errorf("%s: expected Read to refuse the edited file", desc)
		} else if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: an edited file must not read as missing: %v", desc, err)
		}
	}
}
