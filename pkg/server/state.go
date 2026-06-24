// Package server provides the local web server for InfraGuard (`infraguard server`).
package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/aliyun/infraguard/pkg/config"
)

// stateFileName is the name of the server state file under the config directory.
const stateFileName = "server.json"

// State describes a running server instance, persisted to disk so that
// `stop` and `status` can find it.
type State struct {
	PID       int       `json:"pid"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	URL       string    `json:"url"`
	Token     string    `json:"token"`
	StartedAt time.Time `json:"started_at"`
	Version   string    `json:"version"`
}

// StatePath returns the full path to the server state file.
func StatePath() (string, error) {
	dir, err := config.DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, stateFileName), nil
}

// WriteState persists the server state.
func WriteState(s *State) error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ReadState reads the server state, returning (nil, nil) if no state file exists.
func ReadState() (*State, error) {
	path, err := StatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// RemoveState deletes the server state file (ignoring a missing file).
func RemoveState() error {
	path, err := StatePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsRunning reports whether the process recorded in the state is alive.
func (s *State) IsRunning() bool {
	if s == nil || s.PID <= 0 {
		return false
	}
	return ProcessAlive(s.PID)
}
