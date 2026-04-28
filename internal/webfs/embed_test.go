package webfs

import (
	"io/fs"
	"testing"
)

// TestFS_ReturnsSubFS verifies the go:embed wiring even when web/dist/
// is empty (the unit-test path: pre-`make web` builds). FS() must
// always return a usable fs.FS without error; iterating it may yield
// zero entries, which is fine.
func TestFS_ReturnsSubFS(t *testing.T) {
	sub, err := FS()
	if err != nil {
		t.Fatalf("FS: %v", err)
	}
	if sub == nil {
		t.Fatal("FS returned nil")
	}
	// Walk does not error on an empty filesystem.
	if err := fs.WalkDir(sub, ".", func(_ string, _ fs.DirEntry, err error) error {
		return err
	}); err != nil {
		t.Errorf("WalkDir: %v", err)
	}
}
