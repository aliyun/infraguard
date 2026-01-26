package config

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestConfig(t *testing.T) {
	Convey("Config", t, func() {
		// Create a temporary directory for test config
		tempDir, err := os.MkdirTemp("", "infraguard-config-test")
		So(err, ShouldBeNil)
		defer os.RemoveAll(tempDir)

		// Override home directory for testing
		origHome := os.Getenv("HOME")
		origUserProfile := os.Getenv("USERPROFILE")
		os.Setenv("HOME", tempDir)
		os.Setenv("USERPROFILE", tempDir)
		defer func() {
			os.Setenv("HOME", origHome)
			os.Setenv("USERPROFILE", origUserProfile)
		}()

		// Ensure config directory and file are clean at the start
		configDir := filepath.Join(tempDir, ".infraguard")
		os.RemoveAll(configDir)

		Convey("DefaultConfigDir should return correct path", func() {
			dir, err := DefaultConfigDir()
			So(err, ShouldBeNil)
			So(dir, ShouldEqual, filepath.Join(tempDir, ".infraguard"))
		})

		Convey("ConfigPath should return correct path", func() {
			path, err := ConfigPath()
			So(err, ShouldBeNil)
			So(path, ShouldEqual, filepath.Join(tempDir, ".infraguard", "config.yaml"))
		})

		Convey("Load should return empty config when file doesn't exist", func() {
			cfg, err := Load()
			So(err, ShouldBeNil)
			So(cfg, ShouldNotBeNil)
			So(cfg.Lang, ShouldBeEmpty)
		})

		Convey("Save and Load should work correctly", func() {
			cfg := &Config{Lang: "zh"}
			err := Save(cfg)
			So(err, ShouldBeNil)

			loaded, err := Load()
			So(err, ShouldBeNil)
			So(loaded.Lang, ShouldEqual, "zh")
		})

		Convey("Config Get/Set/Unset", func() {
			cfg := &Config{}

			Convey("Get should return empty for unset key", func() {
				So(cfg.Get("lang"), ShouldBeEmpty)
			})

			Convey("Set should update the value", func() {
				cfg.Set("lang", "zh")
				So(cfg.Lang, ShouldEqual, "zh")
				So(cfg.Get("lang"), ShouldEqual, "zh")
			})

			Convey("Unset should clear the value", func() {
				cfg.Set("lang", "zh")
				cfg.Unset("lang")
				So(cfg.Lang, ShouldBeEmpty)
				So(cfg.Get("lang"), ShouldBeEmpty)
			})

			Convey("Get should return empty for unknown key", func() {
				So(cfg.Get("unknown"), ShouldBeEmpty)
			})
		})

		Convey("Config IsEmpty", func() {
			cfg := &Config{}
			So(cfg.IsEmpty(), ShouldBeTrue)

			cfg.Lang = "en"
			So(cfg.IsEmpty(), ShouldBeFalse)
		})

		Convey("Config ToMap", func() {
			cfg := &Config{}
			So(cfg.ToMap(), ShouldBeEmpty)

			cfg.Lang = "zh"
			m := cfg.ToMap()
			So(m, ShouldContainKey, "lang")
			So(m["lang"], ShouldEqual, "zh")
		})

		Convey("IsValidKey", func() {
			So(IsValidKey("lang"), ShouldBeTrue)
			So(IsValidKey("unknown"), ShouldBeFalse)
		})

		Convey("IsValidLang", func() {
			So(IsValidLang("en"), ShouldBeTrue)
			So(IsValidLang("zh"), ShouldBeTrue)
			So(IsValidLang("fr"), ShouldBeFalse)
		})

		Convey("ValidateValue", func() {
			Convey("should accept valid lang values", func() {
				So(ValidateValue("lang", "en"), ShouldBeNil)
				So(ValidateValue("lang", "zh"), ShouldBeNil)
			})

			Convey("should reject invalid lang values", func() {
				err := ValidateValue("lang", "invalid")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "invalid value for lang")
			})
		})

		Convey("GetLang", func() {
			Convey("should return empty when no config exists", func() {
				So(GetLang(), ShouldBeEmpty)
			})

			Convey("should return configured language", func() {
				cfg := &Config{Lang: "zh"}
				err := Save(cfg)
				So(err, ShouldBeNil)

				So(GetLang(), ShouldEqual, "zh")
			})
		})
	})
}
