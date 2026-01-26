package cmd

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/aliyun/infraguard/pkg/updater"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	checkOnly     bool
	forceUpdate   bool
	targetVersion string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update InfraGuard CLI", // Will be updated by i18n
	Long:  "",                      // Will be updated by i18n
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().BoolVar(&checkOnly, "check", false,
		"Check for updates without installing")
	updateCmd.Flags().BoolVar(&forceUpdate, "force", false,
		"Force update even if version is current")
	updateCmd.Flags().StringVar(&targetVersion, "version", "",
		"Update to specific version")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	msg := i18n.Msg()

	// Create updater instance
	u := updater.New(Version)

	// Set progress callback
	u.SetProgressFunc(func(downloaded, total int64) {
		if total > 0 {
			percent := float64(downloaded) / float64(total) * 100
			downloadedStr := formatBytes(downloaded)
			totalStr := formatBytes(total)
			fmt.Printf("\r"+msg.Update.DownloadProgress, downloadedStr, totalStr, percent)
		}
	})

	// Check for updates
	fmt.Println(msg.Update.Checking)
	fmt.Printf(msg.Update.CurrentVersion+"\n", Version)

	var versionToInstall string
	if targetVersion != "" {
		// User specified a version
		versionToInstall = targetVersion
	} else {
		// Get latest version
		latest, err := u.GetLatestVersion()
		if err != nil {
			return fmt.Errorf(msg.Update.Errors.FetchLatest, err)
		}
		fmt.Printf(msg.Update.LatestVersion+"\n", latest)
		versionToInstall = latest
	}

	// Compare versions
	if !forceUpdate {
		cmp, err := u.CompareVersions(versionToInstall)
		if err != nil {
			return fmt.Errorf(msg.Update.Errors.CompareVersions, err)
		}

		if cmp == 0 {
			// Already on target version
			if checkOnly {
				fmt.Println(color.GreenString("✓ ") + msg.Update.AlreadyLatest)
				return nil
			}
			// Not check-only mode, and version is the same
			return fmt.Errorf(msg.Update.Errors.NoUpdateNeeded, Version, versionToInstall)
		} else if cmp > 0 {
			// Current version is newer than target
			fmt.Println(color.YellowString("⚠ ") + fmt.Sprintf(msg.Update.Errors.NoUpdateNeeded, Version, versionToInstall))
			return nil
		}
	}

	// If check-only mode, just inform user
	if checkOnly {
		fmt.Println(color.GreenString("✓ ") + fmt.Sprintf(msg.Update.UpdateAvailable, versionToInstall))
		return nil
	}

	// Proceed with update
	fmt.Println(color.CyanString("→ ") + fmt.Sprintf(msg.Update.Downloading, versionToInstall))

	// Detect platform
	goos, goarch := updater.DetectPlatform()

	// Check if platform is supported
	if !isSupportedPlatform(goos, goarch) {
		return fmt.Errorf(msg.Update.Errors.UnsupportedPlatform, goos, goarch)
	}

	// Download and install
	err := u.DownloadAndInstall(versionToInstall)
	if err != nil {
		// Check for common error types
		errStr := err.Error()
		if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") {
			return fmt.Errorf("%s", msg.Update.Errors.PermissionDenied)
		}
		if strings.Contains(errStr, "rate limit") {
			return fmt.Errorf("%s", msg.Update.Errors.RateLimit)
		}
		if strings.Contains(errStr, "network") || strings.Contains(errStr, "connection") {
			return fmt.Errorf(msg.Update.Errors.NetworkError, err)
		}
		return fmt.Errorf(msg.Update.Errors.InstallFailed, err)
	}

	fmt.Println() // New line after progress

	// Platform-specific success message
	if runtime.GOOS == "windows" {
		fmt.Println(color.GreenString("✓ ") + fmt.Sprintf(msg.Update.SuccessWindows, versionToInstall))
		fmt.Println(color.YellowString("⚠ ") + msg.Update.RestartRequired)
	} else {
		fmt.Println(color.GreenString("✓ ") + fmt.Sprintf(msg.Update.Success, versionToInstall))
		fmt.Println(color.YellowString("⚠ ") + msg.Update.RestartRequiredUnix)
	}

	return nil
}

// formatBytes formats bytes to human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// isSupportedPlatform checks if the platform is supported
func isSupportedPlatform(goos, goarch string) bool {
	supportedPlatforms := map[string][]string{
		"darwin":  {"amd64", "arm64"},
		"linux":   {"amd64", "arm64"},
		"windows": {"amd64", "arm64"},
	}

	if archs, ok := supportedPlatforms[goos]; ok {
		for _, arch := range archs {
			if arch == goarch {
				return true
			}
		}
	}
	return false
}

// updateUpdateCommandDescriptions updates the update command descriptions with i18n
func updateUpdateCommandDescriptions() {
	msg := i18n.Msg()

	updateCmd.Short = i18n.Get(func(m *i18n.Messages) string { return m.Update.Short })
	updateCmd.Long = strings.TrimSpace(i18n.Get(func(m *i18n.Messages) string { return m.Update.Long }))

	// Update flag descriptions
	if f := updateCmd.Flags().Lookup("check"); f != nil {
		f.Usage = msg.Update.CheckFlag
	}
	if f := updateCmd.Flags().Lookup("force"); f != nil {
		f.Usage = msg.Update.ForceFlag
	}
	if f := updateCmd.Flags().Lookup("version"); f != nil {
		f.Usage = msg.Update.VersionFlag
	}
}
