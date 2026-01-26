package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aliyun/infraguard/pkg/models"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown/print"
	. "github.com/smartystreets/goconvey/convey"
)

func TestEvaluate(t *testing.T) {
	Convey("Given the Evaluate function", t, func() {
		Convey("When policy directory does not exist", func() {
			_, err := Evaluate("/nonexistent/path", map[string]interface{}{})

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When policy directory is empty", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-empty")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			_, err = Evaluate(tmpDir, map[string]interface{}{})

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When policy contains invalid rego syntax", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-invalid")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			invalidRego := `package test
this is not valid rego syntax!!!`
			err = os.WriteFile(filepath.Join(tmpDir, "invalid.rego"), []byte(invalidRego), 0644)
			So(err, ShouldBeNil)

			_, err = Evaluate(tmpDir, map[string]interface{}{})

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When evaluating with a simple policy", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-simple")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			complianceDir := filepath.Join(tmpDir, "infraguard", "rules", "test", "compliance")
			err = os.MkdirAll(complianceDir, 0755)
			So(err, ShouldBeNil)

			simplePolicy := `package infraguard.rules.test.compliance

deny contains violation if {
    input.test == true
    violation := {
        "id": "SIMPLE-001",
        "resource_id": "test",
        "violation_path": ["test"],
        "meta": {
            "severity": "Low",
            "reason": "Test violation"
        }
    }
}
`
			err = os.WriteFile(filepath.Join(complianceDir, "simple.rego"), []byte(simplePolicy), 0644)
			So(err, ShouldBeNil)

			Convey("With matching input", func() {
				input := map[string]interface{}{"test": true}
				violations, err := Evaluate(tmpDir, input)

				Convey("It should return 1 violation", func() {
					So(err, ShouldBeNil)
					So(len(violations), ShouldEqual, 1)
				})
			})

			Convey("With non-matching input", func() {
				input := map[string]interface{}{"test": false}
				violations, err := Evaluate(tmpDir, input)

				Convey("It should return no violations", func() {
					So(err, ShouldBeNil)
					So(len(violations), ShouldEqual, 0)
				})
			})
		})

		Convey("When evaluating with a single .rego file", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-single")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			singlePolicy := `package infraguard.rules.test.single

deny contains violation if {
    input.single_test == true
    violation := {
        "id": "SINGLE-001",
        "resource_id": "test",
        "violation_path": ["single_test"],
        "meta": {
            "severity": "Low",
            "reason": "Single file test violation"
        }
    }
}
`
			regoFile := filepath.Join(tmpDir, "single.rego")
			err = os.WriteFile(regoFile, []byte(singlePolicy), 0644)
			So(err, ShouldBeNil)

			input := map[string]interface{}{"single_test": true}
			violations, err := Evaluate(regoFile, input)

			Convey("It should return 1 violation", func() {
				So(err, ShouldBeNil)
				So(len(violations), ShouldEqual, 1)
				So(violations[0].ID, ShouldEqual, "SINGLE-001")
			})
		})

		Convey("When evaluating with a non-.rego file", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-nonrego")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			txtFile := filepath.Join(tmpDir, "policy.txt")
			err = os.WriteFile(txtFile, []byte("not a rego file"), 0644)
			So(err, ShouldBeNil)

			_, err = Evaluate(txtFile, map[string]interface{}{})

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When evaluating with nested policies and helpers", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-nested")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			// Create directory structure: infraguard/rules/test/nested
			rulesDir := filepath.Join(tmpDir, "infraguard", "rules", "test", "nested")
			err = os.MkdirAll(rulesDir, 0755)
			So(err, ShouldBeNil)

			mainPolicy := `package infraguard.rules.test.nested

import data.infraguard.helpers

deny contains violation if {
    input.check == true
    violation := helpers.make_violation("NESTED-001", "resource", "Test")
}
`
			err = os.WriteFile(filepath.Join(rulesDir, "main.rego"), []byte(mainPolicy), 0644)
			So(err, ShouldBeNil)

			helperPolicy := `package infraguard.helpers

make_violation(id, resource, reason) = violation if {
    violation := {
        "id": id,
        "resource_id": resource,
        "meta": {"severity": "Medium", "reason": reason}
    }
}
`
			helpersDir := filepath.Join(tmpDir, "helpers")
			err = os.MkdirAll(helpersDir, 0755)
			So(err, ShouldBeNil)
			err = os.WriteFile(filepath.Join(helpersDir, "helpers.rego"), []byte(helperPolicy), 0644)
			So(err, ShouldBeNil)

			input := map[string]interface{}{"check": true}
			opts := &EvalOptions{
				PolicyPaths: []string{tmpDir},
				LibModules: map[string]string{
					"helpers.rego": helperPolicy,
				},
			}
			evalResult, err := EvaluateWithOpts(opts, input)
			So(err, ShouldBeNil)
			violations := evalResult.Violations

			Convey("It should return 1 violation", func() {
				So(err, ShouldBeNil)
				So(len(violations), ShouldEqual, 1)
			})
		})
	})
}

func TestDiscoverRegoFiles(t *testing.T) {
	Convey("Given the discoverRegoFiles function", t, func() {
		Convey("When discovering files in a directory with rego files", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-discover")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			subDir := filepath.Join(tmpDir, "subdir")
			err = os.MkdirAll(subDir, 0755)
			So(err, ShouldBeNil)

			files := []string{
				filepath.Join(tmpDir, "main.rego"),
				filepath.Join(subDir, "helper.rego"),
			}

			for _, f := range files {
				err = os.WriteFile(f, []byte("package test"), 0644)
				So(err, ShouldBeNil)
			}

			err = os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("test"), 0644)
			So(err, ShouldBeNil)

			discovered, err := discoverRegoFiles(tmpDir)

			Convey("It should return only .rego files", func() {
				So(err, ShouldBeNil)
				So(len(discovered), ShouldEqual, 2)
			})
		})

		Convey("When directory does not exist", func() {
			_, err := discoverRegoFiles("/nonexistent/path")

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When discovering a single .rego file", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-discover-single")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			regoFile := filepath.Join(tmpDir, "single.rego")
			err = os.WriteFile(regoFile, []byte("package test"), 0644)
			So(err, ShouldBeNil)

			files, err := discoverRegoFiles(regoFile)

			Convey("It should return that file", func() {
				So(err, ShouldBeNil)
				So(len(files), ShouldEqual, 1)
				So(files[0], ShouldEqual, regoFile)
			})
		})

		Convey("When discovering a non-.rego file", func() {
			tmpDir, err := os.MkdirTemp("", "engine-test-discover-nonrego")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			txtFile := filepath.Join(tmpDir, "policy.txt")
			err = os.WriteFile(txtFile, []byte("not a rego file"), 0644)
			So(err, ShouldBeNil)

			_, err = discoverRegoFiles(txtFile)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestExpandViolationIDs(t *testing.T) {
	Convey("Given the expandViolationIDs function", t, func() {
		Convey("When expanding short IDs to full IDs", func() {
			violations := []models.OPAViolation{
				{ID: "alb-instance-bind-security-group"},
				{ID: "rds-instance-enabled-tde"},
				{ID: "unknown-rule"},
			}
			idMapping := map[string]string{
				"alb-instance-bind-security-group": "rule:aliyun:alb-instance-bind-security-group",
				"rds-instance-enabled-tde":         "rule:aliyun:rds-instance-enabled-tde",
			}

			expanded := expandViolationIDs(violations, idMapping)

			Convey("It should expand known short IDs", func() {
				So(expanded[0].ID, ShouldEqual, "rule:aliyun:alb-instance-bind-security-group")
				So(expanded[1].ID, ShouldEqual, "rule:aliyun:rds-instance-enabled-tde")
			})

			Convey("It should keep unknown IDs unchanged", func() {
				So(expanded[2].ID, ShouldEqual, "unknown-rule")
			})
		})

		Convey("When mapping is empty", func() {
			violations := []models.OPAViolation{
				{ID: "some-rule"},
			}

			expanded := expandViolationIDs(violations, map[string]string{})

			Convey("It should keep IDs unchanged", func() {
				So(expanded[0].ID, ShouldEqual, "some-rule")
			})
		})
	})
}

func TestFilterViolationsByRuleIDs(t *testing.T) {
	Convey("Given the filterViolationsByRuleIDs function", t, func() {
		violations := []models.OPAViolation{
			{ID: "rule:aliyun:alb-instance-bind-security-group"},
			{ID: "rule:aliyun:rds-instance-enabled-tde"},
			{ID: "rule:aws:kafka-instance-disk-encrypted"},
		}

		Convey("When filtering with exact full rule ID", func() {
			filtered := filterViolationsByRuleIDs(violations, []string{"rule:aliyun:alb-instance-bind-security-group"})

			Convey("It should match exactly", func() {
				So(len(filtered), ShouldEqual, 1)
				So(filtered[0].ID, ShouldEqual, "rule:aliyun:alb-instance-bind-security-group")
			})
		})

		Convey("When filtering with multiple rule IDs from different providers", func() {
			filtered := filterViolationsByRuleIDs(violations, []string{
				"rule:aliyun:alb-instance-bind-security-group",
				"rule:aws:kafka-instance-disk-encrypted",
			})

			Convey("It should match both violations", func() {
				So(len(filtered), ShouldEqual, 2)
			})
		})

		Convey("When filtering with empty rule IDs", func() {
			filtered := filterViolationsByRuleIDs(violations, []string{})

			Convey("It should return all violations", func() {
				So(len(filtered), ShouldEqual, 3)
			})
		})

		Convey("When filtering with non-matching rule ID", func() {
			filtered := filterViolationsByRuleIDs(violations, []string{"rule:aliyun:non-existent-rule"})

			Convey("It should return no violations", func() {
				So(len(filtered), ShouldEqual, 0)
			})
		})

		Convey("When filtering with short ID (no match expected)", func() {
			filtered := filterViolationsByRuleIDs(violations, []string{"alb-instance-bind-security-group"})

			Convey("It should not match (requires exact full ID)", func() {
				So(len(filtered), ShouldEqual, 0)
			})
		})
	})
}

func TestParseViolation(t *testing.T) {
	Convey("Given the parseViolation function", t, func() {
		Convey("When parsing an invalid item", func() {
			ch := make(chan int)
			_, err := parseViolation(ch)

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When parsing a valid item", func() {
			item := map[string]interface{}{
				"id":          "TEST-001",
				"resource_id": "MyResource",
				"meta": map[string]interface{}{
					"severity": "High",
					"reason":   "Test reason",
				},
			}

			v, err := parseViolation(item)

			Convey("It should parse successfully", func() {
				So(err, ShouldBeNil)
				So(v.ID, ShouldEqual, "TEST-001")
				So(v.ResourceID, ShouldEqual, "MyResource")
				So(v.Meta.Severity, ShouldEqual, "High")
			})
		})

		Convey("When parsing an empty map", func() {
			item := map[string]interface{}{}
			v, err := parseViolation(item)

			Convey("It should return empty fields", func() {
				So(err, ShouldBeNil)
				So(v.ID, ShouldBeEmpty)
			})
		})

		Convey("When parsing an item with violation path", func() {
			item := map[string]interface{}{
				"id":             "PATH-001",
				"resource_id":    "MyResource",
				"violation_path": []interface{}{"Resources", "MyResource", "Properties"},
				"meta": map[string]interface{}{
					"severity":       "High",
					"reason":         "Test",
					"recommendation": "Fix it",
				},
			}

			v, err := parseViolation(item)

			Convey("It should parse violation path correctly", func() {
				So(err, ShouldBeNil)
				So(len(v.ViolationPath), ShouldEqual, 3)
				So(v.Meta.Recommendation, ShouldEqual, "Fix it")
			})
		})
	})
}

func TestPrintHook(t *testing.T) {
	Convey("Given the printHook implementation", t, func() {
		hook := &printHook{}

		Convey("When capturing print output with location", func() {
			// Redirect stderr to capture output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			// Create a real print context with location
			location := ast.NewLocation([]byte("test"), "/path/to/policy.rego", 42, 10)
			ctx := print.Context{
				Context:  context.Background(),
				Location: location,
			}

			err := hook.Print(ctx, "test message")

			// Restore stderr and read captured output
			w.Close()
			os.Stderr = oldStderr
			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should include location and message", func() {
				So(output, ShouldContainSubstring, "/path/to/policy.rego")
				So(output, ShouldContainSubstring, "42")
				So(output, ShouldContainSubstring, "test message")
			})
		})

		Convey("When capturing print output without location", func() {
			// Redirect stderr to capture output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			// Create a print context without location
			ctx := print.Context{
				Context:  context.Background(),
				Location: nil,
			}

			err := hook.Print(ctx, "message without location")

			// Restore stderr and read captured output
			w.Close()
			os.Stderr = oldStderr
			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			Convey("It should not return an error", func() {
				So(err, ShouldBeNil)
			})

			Convey("It should output message without location prefix", func() {
				So(output, ShouldEqual, "message without location\n")
			})
		})
	})
}

func TestPrintStatementsIntegration(t *testing.T) {
	Convey("Given a policy with print statements", t, func() {
		tmpDir, err := os.MkdirTemp("", "engine-test-print")
		So(err, ShouldBeNil)
		defer os.RemoveAll(tmpDir)

		// Create a policy with print statements
		rulesDir := filepath.Join(tmpDir, "infraguard", "rules", "test", "print")
		err = os.MkdirAll(rulesDir, 0755)
		So(err, ShouldBeNil)

		printPolicy := `package infraguard.rules.test.print

deny contains violation if {
    print("=== Starting evaluation ===")
    input.test == true
    print("Found test value:", input.test)
    print("Creating violation")
    
    violation := {
        "id": "PRINT-001",
        "resource_id": "test",
        "violation_path": ["test"],
        "meta": {
            "severity": "Low",
            "reason": "Test with print"
        }
    }
}
`
		err = os.WriteFile(filepath.Join(rulesDir, "print_test.rego"), []byte(printPolicy), 0644)
		So(err, ShouldBeNil)

		Convey("When evaluating with print statements enabled", func() {
			// Redirect stderr to capture print output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			input := map[string]interface{}{"test": true}
			violations, err := Evaluate(tmpDir, input)

			// Restore stderr and read captured output
			w.Close()
			os.Stderr = oldStderr
			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			Convey("It should return violations", func() {
				So(err, ShouldBeNil)
				So(len(violations), ShouldEqual, 1)
				So(violations[0].ID, ShouldEqual, "PRINT-001")
			})

			Convey("It should capture print output", func() {
				So(output, ShouldContainSubstring, "Starting evaluation")
				So(output, ShouldContainSubstring, "Found test value:")
				So(output, ShouldContainSubstring, "Creating violation")
			})

			Convey("Print output should include file location", func() {
				So(output, ShouldContainSubstring, "print_test.rego")
			})
		})

		Convey("When evaluating with non-matching input", func() {
			// Redirect stderr to capture print output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			input := map[string]interface{}{"test": false}
			violations, err := Evaluate(tmpDir, input)

			// Restore stderr and read captured output
			w.Close()
			os.Stderr = oldStderr
			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			Convey("It should return no violations", func() {
				So(err, ShouldBeNil)
				So(len(violations), ShouldEqual, 0)
			})

			Convey("It should still capture initial print output", func() {
				So(output, ShouldContainSubstring, "Starting evaluation")
			})

			Convey("It should not capture prints after failed condition", func() {
				So(output, ShouldNotContainSubstring, "Creating violation")
			})
		})
	})
}

func TestPrintWithComplexData(t *testing.T) {
	Convey("Given a policy that prints complex data structures", t, func() {
		tmpDir, err := os.MkdirTemp("", "engine-test-print-complex")
		So(err, ShouldBeNil)
		defer os.RemoveAll(tmpDir)

		rulesDir := filepath.Join(tmpDir, "infraguard", "rules", "test", "complex")
		err = os.MkdirAll(rulesDir, 0755)
		So(err, ShouldBeNil)

		complexPolicy := `package infraguard.rules.test.complex

deny contains violation if {
    print("Input keys:", object.keys(input))
    some key, value in input.resources
    print("Resource:", key, "Type:", value.type)
    
    value.type == "OSS::Bucket"
    
    violation := {
        "id": "COMPLEX-001",
        "resource_id": key,
        "violation_path": ["resources", key],
        "meta": {
            "severity": "Medium",
            "reason": "Complex data test"
        }
    }
}
`
		err = os.WriteFile(filepath.Join(rulesDir, "complex.rego"), []byte(complexPolicy), 0644)
		So(err, ShouldBeNil)

		Convey("When printing complex nested structures", func() {
			// Redirect stderr to capture print output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			input := map[string]interface{}{
				"resources": map[string]interface{}{
					"bucket1": map[string]interface{}{
						"type": "OSS::Bucket",
						"name": "my-bucket",
					},
					"bucket2": map[string]interface{}{
						"type": "ECS::Instance",
						"name": "my-instance",
					},
				},
			}

			violations, err := Evaluate(tmpDir, input)

			// Restore stderr and read captured output
			w.Close()
			os.Stderr = oldStderr
			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			Convey("It should evaluate correctly", func() {
				So(err, ShouldBeNil)
				So(len(violations), ShouldEqual, 1)
			})

			Convey("It should print complex data structures", func() {
				So(output, ShouldContainSubstring, "Input keys:")
				So(output, ShouldContainSubstring, "resources")
				So(output, ShouldContainSubstring, "Resource:")
			})

			Convey("It should print resource iteration details", func() {
				lines := strings.Split(output, "\n")
				resourceLines := 0
				for _, line := range lines {
					if strings.Contains(line, "Resource:") {
						resourceLines++
					}
				}
				// Should iterate through both resources
				So(resourceLines, ShouldBeGreaterThanOrEqualTo, 1)
			})
		})
	})
}
