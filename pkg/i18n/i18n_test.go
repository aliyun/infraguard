package i18n

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSetLanguage(t *testing.T) {
	Convey("Given the SetLanguage function", t, func() {
		Convey("When setting to Chinese", func() {
			SetLanguage("zh")

			Convey("It should return zh", func() {
				So(GetLanguage(), ShouldEqual, "zh")
			})
		})

		Convey("When setting to English", func() {
			SetLanguage("en")

			Convey("It should return en", func() {
				So(GetLanguage(), ShouldEqual, "en")
			})
		})

		Convey("When setting to an invalid language", func() {
			SetLanguage("en") // Reset first
			SetLanguage("invalid")

			Convey("It should remain en", func() {
				So(GetLanguage(), ShouldEqual, "en")
			})
		})

		Convey("When setting to empty string", func() {
			SetLanguage("")
			lang := GetLanguage()

			Convey("It should auto-detect and return en or zh", func() {
				So(lang, ShouldBeIn, []string{"zh", "en"})
			})
		})
	})
}

func TestMsg(t *testing.T) {
	Convey("Given the Msg function", t, func() {
		Convey("When language is English", func() {
			SetLanguage("en")
			msg := Msg()

			Convey("It should return English messages", func() {
				So(msg.Root.Short, ShouldEqual, "InfraGuard - IaC compliance pre-check CLI")
			})
		})

		Convey("When language is Chinese", func() {
			SetLanguage("zh")
			msg := Msg()

			Convey("It should return Chinese messages", func() {
				So(msg.Root.Short, ShouldEqual, "InfraGuard - IaC 合规预检 CLI")
			})

			Reset(func() {
				SetLanguage("en")
			})
		})
	})
}

func TestGet(t *testing.T) {
	Convey("Given the Get function", t, func() {
		Convey("When language is English", func() {
			SetLanguage("en")
			result := Get(func(m *Messages) string { return m.Root.Short })

			Convey("It should return English value", func() {
				So(result, ShouldEqual, "InfraGuard - IaC compliance pre-check CLI")
			})
		})

		Convey("When language is Chinese", func() {
			SetLanguage("zh")
			result := Get(func(m *Messages) string { return m.Root.Short })

			Convey("It should return Chinese value", func() {
				So(result, ShouldEqual, "InfraGuard - IaC 合规预检 CLI")
			})

			Reset(func() {
				SetLanguage("en")
			})
		})

		Convey("When getter returns empty string", func() {
			SetLanguage("en")
			result := Get(func(m *Messages) string { return "" })

			Convey("It should return empty string", func() {
				So(result, ShouldBeEmpty)
			})
		})
	})
}

func TestFormatMessage(t *testing.T) {
	Convey("Given the FormatMessage function", t, func() {
		Convey("When message is a string", func() {
			result := FormatMessage("Hello World", "zh")

			Convey("It should return as-is", func() {
				So(result, ShouldEqual, "Hello World")
			})
		})

		Convey("When message is map[string]interface{}", func() {
			msg := map[string]interface{}{
				"zh": "你好",
				"en": "Hello",
			}

			Convey("It should return Chinese for zh", func() {
				result := FormatMessage(msg, "zh")
				So(result, ShouldEqual, "你好")
			})

			Convey("It should return English for en", func() {
				result := FormatMessage(msg, "en")
				So(result, ShouldEqual, "Hello")
			})
		})

		Convey("When message is map[string]string", func() {
			msg := map[string]string{
				"zh": "你好",
				"en": "Hello",
			}

			result := FormatMessage(msg, "zh")

			Convey("It should return correct value", func() {
				So(result, ShouldEqual, "你好")
			})
		})

		Convey("When requested language is missing", func() {
			msg := map[string]interface{}{
				"en": "English only",
			}

			result := FormatMessage(msg, "zh")

			Convey("It should fallback to English", func() {
				So(result, ShouldEqual, "English only")
			})
		})

		Convey("When both requested lang and English are missing", func() {
			msg := map[string]interface{}{
				"fr": "Bonjour",
			}

			result := FormatMessage(msg, "zh")

			Convey("It should return empty", func() {
				So(result, ShouldBeEmpty)
			})
		})

		Convey("When message is an invalid type", func() {
			Convey("For integer", func() {
				result := FormatMessage(123, "en")
				So(result, ShouldEqual, "Invalid Format")
			})

			Convey("For slice", func() {
				result := FormatMessage([]string{"a", "b"}, "en")
				So(result, ShouldEqual, "Invalid Format")
			})
		})

		Convey("When map[string]interface{} value is not a string", func() {
			msg := map[string]interface{}{
				"en": 123,
			}

			result := FormatMessage(msg, "en")

			Convey("It should return empty", func() {
				So(result, ShouldBeEmpty)
			})
		})

		Convey("When map[string]string fallback is needed", func() {
			msg := map[string]string{
				"en": "English only",
			}

			result := FormatMessage(msg, "zh")

			Convey("It should fallback to English", func() {
				So(result, ShouldEqual, "English only")
			})
		})

		Convey("When map[string]string has no match", func() {
			msg := map[string]string{
				"fr": "Bonjour",
			}

			result := FormatMessage(msg, "zh")

			Convey("It should return empty", func() {
				So(result, ShouldBeEmpty)
			})
		})
	})
}

func TestCobraTemplateStrings(t *testing.T) {
	Convey("Given cobra template strings", t, func() {
		Convey("When language is English", func() {
			SetLanguage("en")
			msg := Msg()

			Convey("It should have correct Usage", func() {
				So(msg.Usage, ShouldEqual, "Usage")
			})

			Convey("It should have correct AvailableCommands", func() {
				So(msg.AvailableCommands, ShouldEqual, "Available Commands")
			})
		})

		Convey("When language is Chinese", func() {
			SetLanguage("zh")
			msg := Msg()

			Convey("It should have correct Usage", func() {
				So(msg.Usage, ShouldEqual, "用法")
			})

			Convey("It should have correct AvailableCommands", func() {
				So(msg.AvailableCommands, ShouldEqual, "可用命令")
			})

			Reset(func() {
				SetLanguage("en")
			})
		})
	})
}

func TestDetectLanguage(t *testing.T) {
	Convey("Given the DetectLanguage function", t, func() {
		lang := DetectLanguage()

		Convey("It should return en or zh", func() {
			So(lang, ShouldBeIn, []string{"zh", "en"})
		})
	})
}

func TestInit(t *testing.T) {
	Convey("Given the Init function", t, func() {
		oldLang := GetLanguage()
		defer SetLanguage(oldLang)

		Init()
		lang := GetLanguage()

		Convey("It should set language to en or zh", func() {
			So(lang, ShouldBeIn, []string{"zh", "en"})
		})
	})
}

func TestLoadLocale_Cached(t *testing.T) {
	Convey("Given the Msg function with caching", t, func() {
		SetLanguage("en")
		msg1 := Msg()

		SetLanguage("en")
		msg2 := Msg()

		Convey("It should return the same cached pointer", func() {
			So(msg1, ShouldEqual, msg2)
		})
	})
}
