package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAliyunConfigPath(t *testing.T) {
	Convey("Given the aliyunConfigPath function", t, func() {
		path := aliyunConfigPath()

		Convey("It should return a non-empty path", func() {
			So(path, ShouldNotBeEmpty)
		})

		Convey("The path should contain .aliyun and config.json", func() {
			So(path, ShouldContainSubstring, ".aliyun")
			So(path, ShouldContainSubstring, "config.json")
		})
	})
}

func TestLoadCredentials(t *testing.T) {
	Convey("Given the LoadCredentials function", t, func() {
		Convey("When config file does not exist", func() {
			tmpDir, err := os.MkdirTemp("", "aliyun-test-empty")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			// Ensure tmpDir is absolute path
			tmpDir, err = filepath.Abs(tmpDir)
			So(err, ShouldBeNil)

			oldHome := os.Getenv("HOME")
			oldUserProfile := os.Getenv("USERPROFILE")
			defer func() {
				os.Setenv("HOME", oldHome)
				os.Setenv("USERPROFILE", oldUserProfile)
			}()
			os.Setenv("HOME", tmpDir)
			os.Setenv("USERPROFILE", tmpDir)

			_, err = LoadCredentials()

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When config file contains valid credentials", func() {
			tmpDir, err := os.MkdirTemp("", "aliyun-config-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			// Ensure tmpDir is absolute path
			tmpDir, err = filepath.Abs(tmpDir)
			So(err, ShouldBeNil)

			aliyunDir := filepath.Join(tmpDir, ".aliyun")
			err = os.MkdirAll(aliyunDir, 0755)
			So(err, ShouldBeNil)

			config := AliyunConfig{
				Current: "default",
				Profiles: []AliyunProfile{
					{
						Name:            "default",
						Mode:            "AK",
						AccessKeyID:     "test-ak-id",
						AccessKeySecret: "test-ak-secret",
						RegionID:        "cn-shanghai",
					},
				},
			}

			data, _ := json.Marshal(config)
			configPath := filepath.Join(aliyunDir, "config.json")
			err = os.WriteFile(configPath, data, 0644)
			So(err, ShouldBeNil)

			oldHome := os.Getenv("HOME")
			oldUserProfile := os.Getenv("USERPROFILE")
			defer func() {
				os.Setenv("HOME", oldHome)
				os.Setenv("USERPROFILE", oldUserProfile)
			}()
			os.Setenv("HOME", tmpDir)
			os.Setenv("USERPROFILE", tmpDir)

			creds, err := LoadCredentials()

			Convey("It should load credentials successfully", func() {
				So(err, ShouldBeNil)
				So(creds.AccessKeyID, ShouldEqual, "test-ak-id")
				So(creds.AccessKeySecret, ShouldEqual, "test-ak-secret")
				So(creds.Region, ShouldEqual, "cn-shanghai")
			})
		})

		Convey("When config file contains invalid JSON", func() {
			tmpDir, err := os.MkdirTemp("", "aliyun-config-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			// Ensure tmpDir is absolute path
			tmpDir, err = filepath.Abs(tmpDir)
			So(err, ShouldBeNil)

			aliyunDir := filepath.Join(tmpDir, ".aliyun")
			err = os.MkdirAll(aliyunDir, 0755)
			So(err, ShouldBeNil)

			configPath := filepath.Join(aliyunDir, "config.json")
			err = os.WriteFile(configPath, []byte("{invalid json}"), 0644)
			So(err, ShouldBeNil)

			oldHome := os.Getenv("HOME")
			oldUserProfile := os.Getenv("USERPROFILE")
			defer func() {
				os.Setenv("HOME", oldHome)
				os.Setenv("USERPROFILE", oldUserProfile)
			}()
			os.Setenv("HOME", tmpDir)
			os.Setenv("USERPROFILE", tmpDir)

			_, err = LoadCredentials()

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When the current profile does not exist", func() {
			tmpDir, err := os.MkdirTemp("", "aliyun-config-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			// Ensure tmpDir is absolute path
			tmpDir, err = filepath.Abs(tmpDir)
			So(err, ShouldBeNil)

			aliyunDir := filepath.Join(tmpDir, ".aliyun")
			err = os.MkdirAll(aliyunDir, 0755)
			So(err, ShouldBeNil)

			config := AliyunConfig{
				Current: "nonexistent",
				Profiles: []AliyunProfile{
					{
						Name:            "default",
						Mode:            "AK",
						AccessKeyID:     "ak",
						AccessKeySecret: "sk",
					},
				},
			}

			data, _ := json.Marshal(config)
			configPath := filepath.Join(aliyunDir, "config.json")
			err = os.WriteFile(configPath, data, 0644)
			So(err, ShouldBeNil)

			oldHome := os.Getenv("HOME")
			oldUserProfile := os.Getenv("USERPROFILE")
			defer func() {
				os.Setenv("HOME", oldHome)
				os.Setenv("USERPROFILE", oldUserProfile)
			}()
			os.Setenv("HOME", tmpDir)
			os.Setenv("USERPROFILE", tmpDir)

			_, err = LoadCredentials()

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})

		Convey("When credentials are empty", func() {
			tmpDir, err := os.MkdirTemp("", "aliyun-config-test")
			So(err, ShouldBeNil)
			defer os.RemoveAll(tmpDir)

			// Ensure tmpDir is absolute path
			tmpDir, err = filepath.Abs(tmpDir)
			So(err, ShouldBeNil)

			aliyunDir := filepath.Join(tmpDir, ".aliyun")
			err = os.MkdirAll(aliyunDir, 0755)
			So(err, ShouldBeNil)

			config := AliyunConfig{
				Current: "default",
				Profiles: []AliyunProfile{
					{
						Name:            "default",
						Mode:            "AK",
						AccessKeyID:     "",
						AccessKeySecret: "",
					},
				},
			}

			data, _ := json.Marshal(config)
			configPath := filepath.Join(aliyunDir, "config.json")
			err = os.WriteFile(configPath, data, 0644)
			So(err, ShouldBeNil)

			oldHome := os.Getenv("HOME")
			oldUserProfile := os.Getenv("USERPROFILE")
			defer func() {
				os.Setenv("HOME", oldHome)
				os.Setenv("USERPROFILE", oldUserProfile)
			}()
			os.Setenv("HOME", tmpDir)
			os.Setenv("USERPROFILE", tmpDir)

			_, err = LoadCredentials()

			Convey("It should return an error", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestAliyunConfigParsing(t *testing.T) {
	Convey("Given a valid Aliyun config JSON", t, func() {
		configJSON := `{
			"current": "prod",
			"profiles": [
				{
					"name": "default",
					"mode": "AK",
					"access_key_id": "ak1",
					"access_key_secret": "sk1",
					"region_id": "cn-hangzhou"
				},
				{
					"name": "prod",
					"mode": "AK",
					"access_key_id": "ak2",
					"access_key_secret": "sk2",
					"region_id": "cn-shanghai"
				}
			]
		}`

		var config AliyunConfig
		err := json.Unmarshal([]byte(configJSON), &config)

		Convey("It should parse without error", func() {
			So(err, ShouldBeNil)
		})

		Convey("It should have the correct current profile", func() {
			So(config.Current, ShouldEqual, "prod")
		})

		Convey("It should have 2 profiles", func() {
			So(len(config.Profiles), ShouldEqual, 2)
		})

		Convey("The current profile should have correct credentials", func() {
			var current *AliyunProfile
			for i := range config.Profiles {
				if config.Profiles[i].Name == config.Current {
					current = &config.Profiles[i]
					break
				}
			}

			So(current, ShouldNotBeNil)
			So(current.AccessKeyID, ShouldEqual, "ak2")
			So(current.RegionID, ShouldEqual, "cn-shanghai")
		})
	})
}
