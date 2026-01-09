package policy

import (
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestValidateFile(t *testing.T) {
	Convey("Given the ValidateFile function", t, func() {
		Convey("When validating a valid rule file", func() {
			result, err := ValidateFile("testdata/validate/valid/valid-rule.rego")

			Convey("It should succeed without errors", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeTrue)
				So(result.FileType, ShouldEqual, "rule")
				So(result.Errors, ShouldBeEmpty)
			})
		})

		Convey("When validating a valid pack file", func() {
			result, err := ValidateFile("testdata/validate/valid/valid-pack.rego")

			Convey("It should succeed without errors", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeTrue)
				So(result.FileType, ShouldEqual, "pack")
				So(result.Errors, ShouldBeEmpty)
			})
		})

		Convey("When validating a rule file missing name", func() {
			result, err := ValidateFile("testdata/validate/invalid/missing-name.rego")

			Convey("It should fail with appropriate error", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeFalse)
				So(result.FileType, ShouldEqual, "rule")
				So(len(result.Errors), ShouldBeGreaterThan, 0)

				// Check for name error
				hasNameError := false
				for _, e := range result.Errors {
					if e.ErrorCode == ErrCodeRuleMissingName {
						hasNameError = true
						break
					}
				}
				So(hasNameError, ShouldBeTrue)
			})
		})

		Convey("When validating a rule file with invalid severity", func() {
			result, err := ValidateFile("testdata/validate/invalid/invalid-severity.rego")

			Convey("It should fail with severity error", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeFalse)

				hasSeverityError := false
				for _, e := range result.Errors {
					if e.ErrorCode == ErrCodeRuleInvalidSeverity {
						hasSeverityError = true
						break
					}
				}
				So(hasSeverityError, ShouldBeTrue)
			})
		})

		Convey("When validating a rule file missing deny", func() {
			result, err := ValidateFile("testdata/validate/invalid/missing-deny.rego")

			Convey("It should fail with deny error", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeFalse)

				hasDenyError := false
				for _, e := range result.Errors {
					if e.ErrorCode == ErrCodeRuleMissingDeny {
						hasDenyError = true
						break
					}
				}
				So(hasDenyError, ShouldBeTrue)
			})
		})

		Convey("When validating a pack file missing rules", func() {
			result, err := ValidateFile("testdata/validate/invalid/pack-missing-rules.rego")

			Convey("It should fail with rules error", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeFalse)
				So(result.FileType, ShouldEqual, "pack")

				hasRulesError := false
				for _, e := range result.Errors {
					if e.ErrorCode == ErrCodePackMissingRules {
						hasRulesError = true
						break
					}
				}
				So(hasRulesError, ShouldBeTrue)
			})
		})

		Convey("When validating a non-existent file", func() {
			result, err := ValidateFile("testdata/validate/nonexistent.rego")

			Convey("It should return a read error", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeFalse)
				So(len(result.Errors), ShouldBeGreaterThan, 0)
				So(result.Errors[0].ErrorCode, ShouldEqual, ErrCodeReadError)
			})
		})
	})
}

func TestValidateDirectory(t *testing.T) {
	Convey("Given the ValidateDirectory function", t, func() {
		Convey("When validating a directory with valid files", func() {
			summary, err := ValidateDirectory("testdata/validate/valid")

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldEqual, 2)
				So(summary.PassedFiles, ShouldEqual, 2)
				So(summary.FailedFiles, ShouldEqual, 0)
			})
		})

		Convey("When validating a directory with invalid files", func() {
			summary, err := ValidateDirectory("testdata/validate/invalid")

			Convey("It should detect failures", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldBeGreaterThan, 0)
				So(summary.FailedFiles, ShouldBeGreaterThan, 0)
			})
		})
	})
}

func TestValidatePolicies(t *testing.T) {
	Convey("Given the ValidatePolicies function", t, func() {
		Convey("When validating a single file", func() {
			summary, err := ValidatePolicies("testdata/validate/valid/valid-rule.rego")

			Convey("It should succeed", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldEqual, 1)
				So(summary.PassedFiles, ShouldEqual, 1)
			})
		})

		Convey("When validating a directory", func() {
			summary, err := ValidatePolicies("testdata/validate/valid")

			Convey("It should validate all files", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldEqual, 2)
			})
		})

		Convey("When validating a non-existent path", func() {
			_, err := ValidatePolicies("testdata/validate/nonexistent")

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestValidateContent(t *testing.T) {
	Convey("Given the ValidateContent function", t, func() {
		Convey("When validating content with syntax error", func() {
			content := `package test
invalid syntax here`
			result, err := ValidateContent(content, "test.rego")

			Convey("It should detect syntax error", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeFalse)
				So(len(result.Errors), ShouldBeGreaterThan, 0)
				So(result.Errors[0].ErrorCode, ShouldEqual, ErrCodeSyntaxError)
			})
		})

		Convey("When validating content with string name (not i18n dict)", func() {
			content := `package aliyun.string_name_rule

import rego.v1

rule_meta := {
	"id": "string-name-rule",
	"name": "Simple String Name",
	"severity": "medium",
	"reason": "Some reason",
	"resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
	false
	result := {
		"id": rule_meta.id,
		"resource_id": "test",
		"violation_path": ["test"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
		},
	}
}`
			result, err := ValidateContent(content, "test.rego")

			Convey("It should accept string name", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeTrue)
			})
		})

		Convey("When validating content without rule_meta or pack_meta", func() {
			content := `package test.helper

import rego.v1

helper_func := true
`
			result, err := ValidateContent(content, "test.rego")

			Convey("It should skip validation (unknown type)", func() {
				So(err, ShouldBeNil)
				So(result, ShouldNotBeNil)
				So(result.Valid, ShouldBeTrue)
				So(result.FileType, ShouldEqual, "unknown")
			})
		})
	})
}

func TestIsValidSeverity(t *testing.T) {
	Convey("Given the isValidSeverity function", t, func() {
		Convey("It should accept valid severity values", func() {
			So(isValidSeverity("high"), ShouldBeTrue)
			So(isValidSeverity("HIGH"), ShouldBeTrue)
			So(isValidSeverity("medium"), ShouldBeTrue)
			So(isValidSeverity("Medium"), ShouldBeTrue)
			So(isValidSeverity("low"), ShouldBeTrue)
			So(isValidSeverity("LOW"), ShouldBeTrue)
		})

		Convey("It should reject invalid severity values", func() {
			So(isValidSeverity("critical"), ShouldBeFalse)
			So(isValidSeverity("info"), ShouldBeFalse)
			So(isValidSeverity(""), ShouldBeFalse)
		})
	})
}

func TestValidationError(t *testing.T) {
	Convey("Given a ValidationError", t, func() {
		Convey("When it has a line number", func() {
			err := &ValidationError{
				FilePath:  "test.rego",
				Line:      10,
				ErrorCode: "TEST_ERROR",
				Message:   "Test error message",
			}

			Convey("Error() should include line number", func() {
				So(err.Error(), ShouldContainSubstring, "test.rego:10:")
			})
		})

		Convey("When it has no line number", func() {
			err := &ValidationError{
				FilePath:  "test.rego",
				Line:      0,
				ErrorCode: "TEST_ERROR",
				Message:   "Test error message",
			}

			Convey("Error() should not include line number", func() {
				So(err.Error(), ShouldEqual, "test.rego: Test error message")
			})
		})
	})
}

func TestValidateRealPolicies(t *testing.T) {
	Convey("Given the ValidatePolicies function with real policies", t, func() {
		rulesDir := filepath.Join("..", "..", "policies", "aliyun", "rules")

		Convey("When validating existing rules directory", func() {
			summary, err := ValidatePolicies(rulesDir)

			Convey("All rules should be valid", func() {
				So(err, ShouldBeNil)
				So(summary, ShouldNotBeNil)
				So(summary.TotalFiles, ShouldBeGreaterThan, 0)
				So(summary.FailedFiles, ShouldEqual, 0)
			})
		})
	})
}
