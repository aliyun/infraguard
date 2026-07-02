package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/i18n"
	"github.com/fatih/color"
	. "github.com/smartystreets/goconvey/convey"
)

func TestPolicyCommand(t *testing.T) {
	Convey("Given the policy command", t, func() {
		Convey("When checking policy list command", func() {
			Convey("Command structure should be correct", func() {
				// Test command structure
				So(policyListCmd.Use, ShouldEqual, "list")
				// Short description is set dynamically by i18n, may be empty during test init
				So(policyListCmd.RunE, ShouldNotBeNil)
			})
		})

		Convey("When executing policy list with type filters", func() {
			i18n.SetLanguage("en")
			updateCommandDescriptions()
			globalLang = ""
			t.Setenv("INFRAGUARD_POLICY_DIR", t.TempDir())
			t.Setenv("INFRAGUARD_WORKSPACE_POLICY_DIR", repoPoliciesDir(t))

			Convey("Without --type", func() {
				output, err := executeRootCaptureStdout("policy", "list")

				Convey("It should print packs and rules", func() {
					So(err, ShouldBeNil)
					So(output, ShouldContainSubstring, "Packs (")
					So(output, ShouldContainSubstring, "Rules (")
					So(output, ShouldContainSubstring, "pack:aliyun:")
					So(output, ShouldContainSubstring, "rule:aliyun:")
				})
			})

			Convey("With --type pack", func() {
				output, err := executeRootCaptureStdout("policy", "list", "--type", "pack")

				Convey("It should only print packs", func() {
					So(err, ShouldBeNil)
					So(output, ShouldContainSubstring, "Packs (")
					So(output, ShouldNotContainSubstring, "Rules (")
					So(output, ShouldContainSubstring, "pack:aliyun:security")
				})
			})

			Convey("With --type rule", func() {
				output, err := executeRootCaptureStdout("policy", "list", "--type", "rule")

				Convey("It should only print rules", func() {
					So(err, ShouldBeNil)
					So(output, ShouldContainSubstring, "Rules (")
					So(output, ShouldNotContainSubstring, "Packs (")
					So(output, ShouldContainSubstring, "rule:aliyun:")
				})
			})

			Convey("With --type scenario-packs", func() {
				_, err := executeRootCaptureStdout("policy", "list", "--type", "scenario-packs")

				Convey("It should reject the removed type filter", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, `invalid --type "scenario-packs"`)
					So(err.Error(), ShouldContainSubstring, "pack, rule")
				})
			})

			Convey("With an invalid --type value", func() {
				_, err := executeRootCaptureStdout("policy", "list", "--type", "invalid")

				Convey("It should return a clear validation error", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, `invalid --type "invalid"`)
					So(err.Error(), ShouldContainSubstring, "pack, rule")
				})
			})

			Convey("With explicit --type all", func() {
				_, err := executeRootCaptureStdout("policy", "list", "--type", "all")

				Convey("It should reject all as an explicit filter value", func() {
					So(err, ShouldNotBeNil)
					So(err.Error(), ShouldContainSubstring, `invalid --type "all"`)
					So(err.Error(), ShouldContainSubstring, "pack, rule")
				})
			})
		})

		Convey("When executing policy get command", func() {
			Convey("With missing argument", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "get"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					So(errMsg, ShouldContainSubstring, "accepts 1 arg(s)")
				})
			})

			Convey("With invalid policy ID", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "get", "invalid:policy:id"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					hasError := strings.Contains(errMsg, "not found") ||
						strings.Contains(errMsg, "policy") ||
						strings.Contains(errMsg, "error")
					So(hasError, ShouldBeTrue)
				})
			})
		})

		Convey("When executing policy validate command", func() {
			Convey("With missing argument", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "validate"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					So(errMsg, ShouldContainSubstring, "accepts 1 arg(s)")
				})
			})

			Convey("With non-existent file", func() {
				tmpDir := t.TempDir()
				nonExistentPath := filepath.Join(tmpDir, "nonexistent.rego")
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "validate", nonExistentPath})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					hasError := strings.Contains(errMsg, "not found") ||
						strings.Contains(errMsg, "no such file") ||
						strings.Contains(errMsg, "cannot find") ||
						strings.Contains(errMsg, "does not exist") ||
						strings.Contains(errMsg, "path does not exist")
					So(hasError, ShouldBeTrue)
				})
			})
		})

		Convey("When executing policy format command", func() {
			Convey("With missing argument", func() {
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "format"})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					So(errMsg, ShouldContainSubstring, "accepts 1 arg(s)")
				})
			})

			Convey("With non-existent file", func() {
				tmpDir := t.TempDir()
				nonExistentPath := filepath.Join(tmpDir, "nonexistent.rego")
				var buf bytes.Buffer
				rootCmd.SetArgs([]string{"policy", "format", nonExistentPath})
				rootCmd.SetOutput(&buf)
				err := rootCmd.Execute()

				Convey("It should return an error", func() {
					So(err, ShouldNotBeNil)
					errMsg := strings.ToLower(err.Error())
					hasError := strings.Contains(errMsg, "not found") ||
						strings.Contains(errMsg, "no such file") ||
						strings.Contains(errMsg, "cannot find") ||
						strings.Contains(errMsg, "does not exist") ||
						strings.Contains(errMsg, "path does not exist")
					So(hasError, ShouldBeTrue)
				})
			})
		})

		Convey("When checking policy update command", func() {
			Convey("Command structure should be correct", func() {
				// Test command structure without actually executing network operations
				// Policy update requires network access and may prompt for GitHub credentials
				So(policyUpdateCmd.Use, ShouldEqual, "update")
				// Short description is set dynamically by i18n, may be empty during test init
				So(policyUpdateCmd.RunE, ShouldNotBeNil)
			})

			Convey("Command flags should be defined", func() {
				// Verify flags are properly defined
				repoFlag := policyUpdateCmd.Flags().Lookup("repo")
				So(repoFlag, ShouldNotBeNil)

				versionFlag := policyUpdateCmd.Flags().Lookup("version")
				So(versionFlag, ShouldNotBeNil)
			})
		})

		Convey("When checking policy clean command", func() {
			Convey("Command structure should be correct", func() {
				So(policyCleanCmd.Use, ShouldEqual, "clean")
				So(policyCleanCmd.RunE, ShouldNotBeNil)
			})

			Convey("Command flags should be defined", func() {
				forceFlag := policyCleanCmd.Flags().Lookup("force")
				So(forceFlag, ShouldNotBeNil)
				So(forceFlag.Shorthand, ShouldEqual, "f")
			})
		})
	})
}

func repoPoliciesDir(t *testing.T) string {
	t.Helper()

	policiesDir, err := filepath.Abs(filepath.Join("..", "..", "..", "policies"))
	if err != nil {
		t.Fatalf("resolve policies dir: %v", err)
	}
	return policiesDir
}

func executeRootCaptureStdout(args ...string) (string, error) {
	oldStdout := os.Stdout
	oldColorOutput := color.Output
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(&buf, r)
		done <- copyErr
	}()

	os.Stdout = w
	color.Output = w
	rootCmd.SetOutput(w)
	rootCmd.SetErr(w)
	rootCmd.SetArgs(args)
	resetPolicyListTypeFlag()

	execErr := rootCmd.Execute()
	_ = w.Close()
	os.Stdout = oldStdout
	color.Output = oldColorOutput
	rootCmd.SetOutput(oldStdout)
	rootCmd.SetErr(os.Stderr)

	copyErr := <-done
	_ = r.Close()
	if copyErr != nil {
		return buf.String(), copyErr
	}
	return buf.String(), execErr
}

func resetPolicyListTypeFlag() {
	policyListType = ""
	flag := policyListCmd.Flags().Lookup("type")
	if flag == nil {
		return
	}
	_ = flag.Value.Set("")
	flag.Changed = false
}
