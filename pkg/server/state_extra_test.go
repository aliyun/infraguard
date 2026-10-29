package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateErrorsWhenHomeUnavailable(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, err := StatePath(); err == nil {
		t.Fatal("missing home accepted for state path")
	}
	if err := WriteState(&State{}); err == nil {
		t.Fatal("missing home accepted for write")
	}
	if _, err := ReadState(); err == nil {
		t.Fatal("missing home accepted for read")
	}
	if err := RemoveState(); err == nil {
		t.Fatal("missing home accepted for removal")
	}
}

func TestStateFileErrors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configDir := filepath.Join(home, ".infraguard")
	if err := os.WriteFile(configDir, []byte("blocking file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := WriteState(&State{PID: 1}); err == nil {
		t.Fatal("write through file accepted")
	}
	if err := os.Remove(configDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(configDir, stateFileName)
	if err := os.WriteFile(path, []byte("invalid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(); err == nil {
		t.Fatal("invalid state accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(); err == nil {
		t.Fatal("directory accepted as state file")
	}
	if err := WriteState(&State{PID: 1}); err == nil {
		t.Fatal("directory accepted as output file")
	}
	if err := os.WriteFile(filepath.Join(path, "child"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveState(); err == nil {
		t.Fatal("nonempty directory removed as state file")
	}
}
