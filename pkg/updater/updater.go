package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
)

const (
	githubAPIURL     = "https://api.github.com/repos/aliyun/infraguard/releases"
	downloadTimeout  = 5 * time.Minute
	progressInterval = 100 * time.Millisecond
)

// Release represents a GitHub release
type Release struct {
	TagName    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

// Asset represents a release asset
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Updater handles CLI updates
type Updater struct {
	currentVersion string
	owner          string
	repo           string
	httpClient     *http.Client
	progressFunc   ProgressFunc
}

// ProgressFunc is called during download to report progress
type ProgressFunc func(downloaded, total int64)

// New creates a new Updater instance
func New(currentVersion string) *Updater {
	return &Updater{
		currentVersion: currentVersion,
		owner:          "aliyun",
		repo:           "infraguard",
		httpClient: &http.Client{
			Timeout: downloadTimeout,
		},
	}
}

// SetProgressFunc sets the progress callback function
func (u *Updater) SetProgressFunc(fn ProgressFunc) {
	u.progressFunc = fn
}

// GetLatestVersion fetches the latest release version from GitHub
func (u *Updater) GetLatestVersion() (string, error) {
	releases, err := u.fetchReleases()
	if err != nil {
		return "", err
	}

	// Find the latest non-prerelease version
	for _, release := range releases {
		if !release.Prerelease && release.TagName != "" {
			// Remove 'v' prefix if present
			version := strings.TrimPrefix(release.TagName, "v")
			return version, nil
		}
	}

	return "", fmt.Errorf("no stable release found")
}

// GetSpecificVersion fetches a specific release version from GitHub
func (u *Updater) GetSpecificVersion(targetVersion string) (*Release, error) {
	releases, err := u.fetchReleases()
	if err != nil {
		return nil, err
	}

	// Normalize target version (remove 'v' prefix if present)
	targetVersion = strings.TrimPrefix(targetVersion, "v")

	for _, release := range releases {
		releaseVersion := strings.TrimPrefix(release.TagName, "v")
		if releaseVersion == targetVersion {
			return &release, nil
		}
	}

	return nil, fmt.Errorf("version %s not found", targetVersion)
}

// fetchReleases fetches all releases from GitHub API
func (u *Updater) fetchReleases() ([]Release, error) {
	url := fmt.Sprintf("%s/latest", githubAPIURL)
	if strings.Contains(githubAPIURL, "repos") {
		// Get all releases instead of just latest
		url = githubAPIURL
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch releases: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("GitHub API rate limit exceeded. Please try again later or authenticate with a token")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return releases, nil
}

// CompareVersions compares current version with target version
// Returns: -1 if current < target, 0 if equal, 1 if current > target
func (u *Updater) CompareVersions(targetVersion string) (int, error) {
	// Handle development versions
	if strings.Contains(u.currentVersion, "dev") || u.currentVersion == "0.0.0" {
		return -1, nil
	}

	current, err := version.NewVersion(u.currentVersion)
	if err != nil {
		return 0, fmt.Errorf("invalid current version: %w", err)
	}

	target, err := version.NewVersion(targetVersion)
	if err != nil {
		return 0, fmt.Errorf("invalid target version: %w", err)
	}

	// hashicorp/go-version Compare returns:
	// -1 if current < target
	//  0 if current == target
	//  1 if current > target
	// This matches our expected semantics
	if current.LessThan(target) {
		return -1, nil
	} else if current.Equal(target) {
		return 0, nil
	} else {
		return 1, nil
	}
}

// NeedsUpdate checks if an update is available
func (u *Updater) NeedsUpdate(targetVersion string) (bool, error) {
	cmp, err := u.CompareVersions(targetVersion)
	if err != nil {
		return false, err
	}
	return cmp < 0, nil
}

// DetectPlatform returns the current OS and architecture
func DetectPlatform() (goos, goarch string) {
	return runtime.GOOS, runtime.GOARCH
}

// GetAssetName generates the expected asset name for the current platform
// Format: infraguard-vVERSION-OS-ARCH
func GetAssetName(version, goos, goarch string) string {
	// Ensure version has 'v' prefix
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	return fmt.Sprintf("infraguard-%s-%s-%s", version, goos, goarch)
}

// DownloadAndInstall downloads the binary and installs it
func (u *Updater) DownloadAndInstall(targetVersion string) error {
	// Get the specific release
	release, err := u.GetSpecificVersion(targetVersion)
	if err != nil {
		return err
	}

	// Detect platform
	goos, goarch := DetectPlatform()
	assetName := GetAssetName(targetVersion, goos, goarch)

	// Find the matching asset
	var asset *Asset
	for i := range release.Assets {
		if release.Assets[i].Name == assetName {
			asset = &release.Assets[i]
			break
		}
	}

	if asset == nil {
		return fmt.Errorf("no binary found for %s/%s (expected: %s)", goos, goarch, assetName)
	}

	// Download the binary
	tmpFile, err := u.downloadAsset(asset)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer os.Remove(tmpFile)

	// Replace current binary (tmpFile is the binary directly)
	if err := replaceBinary(tmpFile); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	return nil
}

// downloadAsset downloads an asset to a temporary file
func (u *Updater) downloadAsset(asset *Asset) (string, error) {
	req, err := http.NewRequest("GET", asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	// Create temporary file (binary, not archive)
	tmpFile, err := os.CreateTemp("", "infraguard-update-*")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Set executable permissions on the temporary file
	if err := os.Chmod(tmpFile.Name(), 0755); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to set executable permissions: %w", err)
	}

	// Download with progress tracking
	var downloaded int64
	totalSize := asset.Size

	reader := io.TeeReader(resp.Body, &progressWriter{
		total:    totalSize,
		current:  &downloaded,
		callback: u.progressFunc,
	})

	if _, err := io.Copy(tmpFile, reader); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

// progressWriter wraps io.Writer to track progress
type progressWriter struct {
	total    int64
	current  *int64
	callback ProgressFunc
	lastCall time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n := len(p)
	*pw.current += int64(n)

	// Call progress callback with rate limiting
	if pw.callback != nil && time.Since(pw.lastCall) > progressInterval {
		pw.callback(*pw.current, pw.total)
		pw.lastCall = time.Now()
	}

	return n, nil
}

// replaceBinary replaces the current binary with the new one
func replaceBinary(newBinaryPath string) error {
	// Get current executable path
	currentPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current executable path: %w", err)
	}

	// Resolve symlinks (Unix-like systems)
	currentPath, err = filepath.EvalSymlinks(currentPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Windows requires special handling because running executables cannot be replaced
	if runtime.GOOS == "windows" {
		return replaceWindowsBinary(newBinaryPath, currentPath)
	}

	// Unix-like systems: direct replacement
	if err := replaceUnixBinary(newBinaryPath, currentPath); err != nil {
		return err
	}

	// On macOS, remove quarantine attributes to prevent Gatekeeper from blocking execution
	if runtime.GOOS == "darwin" {
		if err := removeQuarantineAttributes(currentPath); err != nil {
			return fmt.Errorf("failed to prepare binary for execution: %w", err)
		}
	}

	return nil
}

// replaceUnixBinary handles binary replacement on Unix-like systems
func replaceUnixBinary(newBinaryPath, currentPath string) error {
	// Create backup
	backupPath := currentPath + ".backup"
	if err := copyFile(currentPath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Attempt to replace binary
	if err := copyFile(newBinaryPath, currentPath); err != nil {
		// Rollback on failure
		_ = copyFile(backupPath, currentPath)
		os.Remove(backupPath)
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(currentPath, 0755); err != nil {
		// Rollback on failure
		_ = copyFile(backupPath, currentPath)
		os.Remove(backupPath)
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Clean up backup
	os.Remove(backupPath)

	return nil
}

// replaceWindowsBinary handles binary replacement on Windows
// Windows locks running executables, so we use a rename strategy:
// 1. Rename current binary to .old
// 2. Copy new binary to original location
// 3. The .old file will be deleted on next update or manually
func replaceWindowsBinary(newBinaryPath, currentPath string) error {
	oldPath := currentPath + ".old"

	// Remove any existing .old file from previous update
	if _, err := os.Stat(oldPath); err == nil {
		// Try to remove it, but don't fail if we can't
		// (it might be locked by another process)
		_ = os.Remove(oldPath)
	}

	// Rename current binary to .old
	// This works even for running executables on Windows
	if err := os.Rename(currentPath, oldPath); err != nil {
		return fmt.Errorf("failed to rename current binary: %w", err)
	}

	// Copy new binary to original location
	if err := copyFile(newBinaryPath, currentPath); err != nil {
		// Rollback: try to restore the original
		_ = os.Rename(oldPath, currentPath)
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	// Success - the .old file will be cleaned up on next update
	// We can't delete it now because the current process might still be using it
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	// Copy permissions
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, sourceInfo.Mode())
}

// removeQuarantineAttributes removes macOS quarantine attributes from a file
// and re-signs it to prevent Gatekeeper from blocking execution.
//
// This function is necessary because:
//  1. Files downloaded via HTTP (even through Go's http.Client) get automatically
//     tagged with com.apple.provenance extended attribute by macOS
//  2. GitHub releases binaries are not code-signed, so Gatekeeper rejects them
//  3. go install works because it compiles locally and Go automatically signs
//     the binary with an ad-hoc signature
//
// By clearing extended attributes and re-signing with ad-hoc signature, we
// make downloaded binaries behave like locally compiled ones.
func removeQuarantineAttributes(path string) error {
	// Step 1: Clear all extended attributes (quarantine, provenance, etc.)
	// This removes the "downloaded from internet" marker that macOS adds
	cmd := exec.Command("xattr", "-c", path)
	if err := cmd.Run(); err != nil {
		// If xattr command fails, try individual attributes
		_ = exec.Command("xattr", "-d", "com.apple.quarantine", path).Run()
	}

	// Step 2: Re-sign the binary with ad-hoc signature
	// This is critical on macOS to prevent the system from killing the process
	cmd = exec.Command("codesign", "--force", "--deep", "--sign", "-", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to re-sign binary: %w", err)
	}

	return nil
}
