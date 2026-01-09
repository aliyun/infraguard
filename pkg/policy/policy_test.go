package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	. "github.com/smartystreets/goconvey/convey"
)

func TestDefaultPolicyDir(t *testing.T) {
	Convey("Given the DefaultPolicyDir function", t, func() {
		Convey("When INFRAGUARD_POLICY_DIR is set", func() {
			tmpDir, err := os.MkdirTemp("", "policy-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			oldEnv := os.Getenv("INFRAGUARD_POLICY_DIR")
			defer os.Setenv("INFRAGUARD_POLICY_DIR", oldEnv)

			os.Setenv("INFRAGUARD_POLICY_DIR", tmpDir)
			dir := DefaultPolicyDir()

			Convey("It should return the env var value", func() {
				So(dir, ShouldEqual, tmpDir)
			})
		})

		Convey("When INFRAGUARD_POLICY_DIR is not set", func() {
			oldEnv := os.Getenv("INFRAGUARD_POLICY_DIR")
			defer os.Setenv("INFRAGUARD_POLICY_DIR", oldEnv)

			os.Unsetenv("INFRAGUARD_POLICY_DIR")
			dir := DefaultPolicyDir()

			Convey("It should return a non-empty default path", func() {
				So(dir, ShouldNotBeEmpty)
			})

			Convey("It should contain .infraguard and policies", func() {
				So(dir, ShouldContainSubstring, ".infraguard")
				So(dir, ShouldContainSubstring, "policies")
			})
		})
	})
}

func TestNewManager(t *testing.T) {
	Convey("Given the NewManager function", t, func() {
		manager := NewManager("/test/path")

		Convey("It should return a non-nil manager", func() {
			So(manager, ShouldNotBeNil)
		})

		Convey("It should have the correct policyDir", func() {
			So(manager.policyDir, ShouldEqual, "/test/path")
		})
	})
}

func TestValidatePath(t *testing.T) {
	Convey("Given the ValidatePath function", t, func() {
		Convey("When path is a single .rego file", func() {
			tmpDir, err := os.MkdirTemp("", "policy-test-single")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			regoFile := filepath.Join(tmpDir, "policy.rego")
			err = os.WriteFile(regoFile, []byte("package test"), 0644)
			So(err, ShouldBeNil)

			err = ValidatePath(regoFile)

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
			})
		})

		Convey("When path is a non-.rego file", func() {
			tmpDir, err := os.MkdirTemp("", "policy-test-nonrego")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			txtFile := filepath.Join(tmpDir, "policy.txt")
			err = os.WriteFile(txtFile, []byte("not a rego file"), 0644)
			So(err, ShouldBeNil)

			err = ValidatePath(txtFile)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestDiscoverRegoFiles(t *testing.T) {
	Convey("Given the DiscoverRegoFiles function", t, func() {
		Convey("When path is a single .rego file", func() {
			tmpDir, err := os.MkdirTemp("", "policy-test-discover-single")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			regoFile := filepath.Join(tmpDir, "single.rego")
			err = os.WriteFile(regoFile, []byte("package test"), 0644)
			So(err, ShouldBeNil)

			files, err := DiscoverRegoFiles(regoFile)

			Convey("It should return that file", func() {
				So(err, ShouldBeNil)
				So(len(files), ShouldEqual, 1)
				So(files[0], ShouldEqual, regoFile)
			})
		})

		Convey("When path is a non-.rego file", func() {
			tmpDir, err := os.MkdirTemp("", "policy-test-discover-nonrego")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			txtFile := filepath.Join(tmpDir, "policy.txt")
			err = os.WriteFile(txtFile, []byte("not a rego file"), 0644)
			So(err, ShouldBeNil)

			_, err = DiscoverRegoFiles(txtFile)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestBuildGetterURL(t *testing.T) {
	Convey("Given the buildGetterURL function", t, func() {
		tests := []struct {
			name     string
			repo     string
			version  string
			expected string
		}{
			{
				name:     "host/path format",
				repo:     "github.com/aliyun/infraguard",
				version:  "main",
				expected: "git::https://github.com/aliyun/infraguard.git//policies?ref=main",
			},
			{
				name:     "HTTPS URL",
				repo:     "https://github.com/aliyun/infraguard.git",
				version:  "v1.0.0",
				expected: "git::https://github.com/aliyun/infraguard.git//policies?ref=v1.0.0",
			},
			{
				name:     "HTTPS URL without .git",
				repo:     "https://github.com/aliyun/infraguard",
				version:  "main",
				expected: "git::https://github.com/aliyun/infraguard.git//policies?ref=main",
			},
			{
				name:     "SSH URL",
				repo:     "ssh://git@github.com/aliyun/infraguard.git",
				version:  "main",
				expected: "git::ssh://git@github.com/aliyun/infraguard.git//policies?ref=main",
			},
			{
				name:     "SCP-like format",
				repo:     "git@github.com:aliyun/infraguard.git",
				version:  "main",
				expected: "git::ssh://git@github.com/aliyun/infraguard.git//policies?ref=main",
			},
			{
				name:     "SCP-like format without .git",
				repo:     "git@github.com:aliyun/infraguard",
				version:  "develop",
				expected: "git::ssh://git@github.com/aliyun/infraguard.git//policies?ref=develop",
			},
		}

		for _, tc := range tests {
			Convey("When repo is "+tc.name, func() {
				result := buildGetterURL(tc.repo, tc.version)

				Convey("It should return correct URL", func() {
					So(result, ShouldEqual, tc.expected)
				})
			})
		}

		Convey("When repo has whitespace", func() {
			result := buildGetterURL("  github.com/org/repo  ", "main")

			Convey("It should trim whitespace", func() {
				So(result, ShouldEqual, "git::https://github.com/org/repo.git//policies?ref=main")
			})
		})

		Convey("When SSH URL without .git", func() {
			result := buildGetterURL("ssh://git@github.com/org/repo", "v1.0")

			Convey("It should add .git suffix", func() {
				So(result, ShouldEqual, "git::ssh://git@github.com/org/repo.git//policies?ref=v1.0")
			})
		})
	})
}

func TestManagerUpdate(t *testing.T) {
	Convey("Given a Manager", t, func() {
		tmpDir, err := os.MkdirTemp("", "policy-update-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(tmpDir)

		manager := NewManager(tmpDir)

		Convey("When updating with invalid repository", func() {
			err := manager.Update("file:///nonexistent/path/that/does/not/exist", "main")

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestMatchPattern(t *testing.T) {
	Convey("Given the MatchPattern function", t, func() {
		Convey("When pattern is exactly '*'", func() {
			Convey("It should match all IDs", func() {
				So(MatchPattern("*", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeTrue)
				So(MatchPattern("*", "pack:aliyun:security-group-best-practice"), ShouldBeTrue)
				So(MatchPattern("*", "anything"), ShouldBeTrue)
			})
		})

		Convey("When pattern has no wildcard", func() {
			Convey("It should do exact match", func() {
				So(MatchPattern("rule:aliyun:ecs-instance-no-public-ip", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:ecs-instance-no-public-ip", "rule:aliyun:rds-instance-enabled-tde"), ShouldBeFalse)
			})
		})

		Convey("When pattern has prefix wildcard", func() {
			Convey("It should match prefix patterns", func() {
				So(MatchPattern("rule:aliyun:ecs-*", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:ecs-*", "rule:aliyun:ecs-security-group-not-open-all-port"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:ecs-*", "rule:aliyun:rds-instance-enabled-tde"), ShouldBeFalse)
			})
		})

		Convey("When pattern has suffix wildcard", func() {
			Convey("It should match suffix patterns", func() {
				So(MatchPattern("rule:aliyun:*-multi-zone", "rule:aliyun:rds-instance-multi-zone"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:*-multi-zone", "rule:aliyun:ecs-instance-multi-zone"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:*-multi-zone", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeFalse)
			})
		})

		Convey("When pattern has substring wildcard", func() {
			Convey("It should match substring patterns", func() {
				So(MatchPattern("rule:aliyun:*multi*", "rule:aliyun:rds-instance-multi-zone"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:*multi*", "rule:aliyun:ecs-instance-multi-zone"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:*multi*", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeFalse)
			})
		})

		Convey("When pattern has multiple wildcards", func() {
			Convey("It should match complex patterns", func() {
				So(MatchPattern("rule:aliyun:*instance*", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:*instance*", "rule:aliyun:rds-instance-enabled-tde"), ShouldBeTrue)
				So(MatchPattern("rule:aliyun:*instance*", "rule:aliyun:security-group"), ShouldBeFalse)
			})
		})

		Convey("When pattern matches pack IDs", func() {
			Convey("It should match pack patterns", func() {
				So(MatchPattern("pack:aliyun:ecs-*", "pack:aliyun:ecs-best-practice"), ShouldBeTrue)
				So(MatchPattern("pack:aliyun:ecs-*", "pack:aliyun:ecs-security-baseline"), ShouldBeTrue)
				So(MatchPattern("pack:aliyun:*-compliance-pack", "pack:aliyun:mlps-level-3-pre-check-compliance-pack"), ShouldBeTrue)
			})
		})

		Convey("When pattern is empty", func() {
			Convey("It should only match empty string", func() {
				So(MatchPattern("", ""), ShouldBeTrue)
				So(MatchPattern("", "rule:aliyun:ecs-instance-no-public-ip"), ShouldBeFalse)
			})
		})
	})
}

func TestLoaderMatchRules(t *testing.T) {
	Convey("Given a Loader with rules", t, func() {
		loader := &Loader{
			index: &models.PolicyIndex{
				Rules:    make(map[string]*models.Rule),
				Packs:    make(map[string]*models.Pack),
				RuleList: []*models.Rule{},
				PackList: []*models.Pack{},
			},
		}

		// Add test rules
		rules := []*models.Rule{
			{ID: "rule:aliyun:ecs-instance-no-public-ip"},
			{ID: "rule:aliyun:ecs-security-group-not-open-all-port"},
			{ID: "rule:aliyun:rds-instance-enabled-tde"},
			{ID: "rule:aliyun:rds-instance-multi-zone"},
		}
		for _, rule := range rules {
			loader.index.AddRule(rule)
		}

		Convey("When matching with prefix pattern", func() {
			matches := loader.MatchRules("rule:aliyun:ecs-*")

			Convey("It should return matching rules", func() {
				So(len(matches), ShouldEqual, 2)
				ruleIDs := make(map[string]bool)
				for _, rule := range matches {
					ruleIDs[rule.ID] = true
				}
				So(ruleIDs["rule:aliyun:ecs-instance-no-public-ip"], ShouldBeTrue)
				So(ruleIDs["rule:aliyun:ecs-security-group-not-open-all-port"], ShouldBeTrue)
			})
		})

		Convey("When matching with suffix pattern", func() {
			matches := loader.MatchRules("rule:aliyun:*-multi-zone")

			Convey("It should return matching rules", func() {
				So(len(matches), ShouldEqual, 1)
				So(matches[0].ID, ShouldEqual, "rule:aliyun:rds-instance-multi-zone")
			})
		})

		Convey("When matching with wildcard pattern", func() {
			matches := loader.MatchRules("rule:*")

			Convey("It should return all rules", func() {
				So(len(matches), ShouldEqual, 4)
			})
		})

		Convey("When matching with pattern that matches nothing", func() {
			matches := loader.MatchRules("rule:aliyun:nonexistent-*")

			Convey("It should return empty slice", func() {
				So(len(matches), ShouldEqual, 0)
			})
		})
	})
}

func TestLoaderMatchPacks(t *testing.T) {
	Convey("Given a Loader with packs", t, func() {
		loader := &Loader{
			index: &models.PolicyIndex{
				Rules:    make(map[string]*models.Rule),
				Packs:    make(map[string]*models.Pack),
				RuleList: []*models.Rule{},
				PackList: []*models.Pack{},
			},
		}

		// Add test packs
		packs := []*models.Pack{
			{ID: "pack:aliyun:ecs-best-practice"},
			{ID: "pack:aliyun:ecs-security-baseline"},
			{ID: "pack:aliyun:mlps-level-3-pre-check-compliance-pack"},
		}
		for _, pack := range packs {
			loader.index.AddPack(pack)
		}

		Convey("When matching with prefix pattern", func() {
			matches := loader.MatchPacks("pack:aliyun:ecs-*")

			Convey("It should return matching packs", func() {
				So(len(matches), ShouldEqual, 2)
				packIDs := make(map[string]bool)
				for _, pack := range matches {
					packIDs[pack.ID] = true
				}
				So(packIDs["pack:aliyun:ecs-best-practice"], ShouldBeTrue)
				So(packIDs["pack:aliyun:ecs-security-baseline"], ShouldBeTrue)
			})
		})

		Convey("When matching with suffix pattern", func() {
			matches := loader.MatchPacks("pack:aliyun:*-compliance-pack")

			Convey("It should return matching packs", func() {
				So(len(matches), ShouldEqual, 1)
				So(matches[0].ID, ShouldEqual, "pack:aliyun:mlps-level-3-pre-check-compliance-pack")
			})
		})

		Convey("When matching with wildcard pattern", func() {
			matches := loader.MatchPacks("pack:*")

			Convey("It should return all packs", func() {
				So(len(matches), ShouldEqual, 3)
			})
		})

		Convey("When matching with pattern that matches nothing", func() {
			matches := loader.MatchPacks("pack:aliyun:nonexistent-*")

			Convey("It should return empty slice", func() {
				So(len(matches), ShouldEqual, 0)
			})
		})
	})
}
