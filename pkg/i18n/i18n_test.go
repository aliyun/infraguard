package i18n

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestSetLanguage(t *testing.T) {
	Convey("Given the SetLanguage function", t, func() {
		Convey("When setting to Chinese", func() {
			SetLanguage("zh")

			Convey("It should normalize to zh-CN", func() {
				So(GetLanguage(), ShouldEqual, "zh-CN")
			})
		})

		Convey("When setting to English", func() {
			SetLanguage("en")

			Convey("It should normalize to en-US", func() {
				So(GetLanguage(), ShouldEqual, "en-US")
			})
		})

		Convey("When setting to an invalid language", func() {
			SetLanguage("en") // Reset first
			SetLanguage("invalid")

			Convey("It should remain en-US", func() {
				So(GetLanguage(), ShouldEqual, "en-US")
			})
		})

		Convey("When setting to empty string", func() {
			SetLanguage("")
			lang := GetLanguage()

			Convey("It should auto-detect and return a BCP 47 tag", func() {
				So(lang, ShouldBeIn, []string{"zh-CN", "en-US", "zh", "en"})
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

		Convey("It should return a BCP 47 language tag", func() {
			So(lang, ShouldBeIn, []string{"zh-CN", "en-US", "zh", "en", "es-ES", "fr-FR", "de-DE", "ja-JP", "pt-BR"})
		})
	})
}

func TestInit(t *testing.T) {
	Convey("Given the Init function", t, func() {
		oldLang := GetLanguage()
		defer SetLanguage(oldLang)

		Init()
		lang := GetLanguage()

		Convey("It should set language to a BCP 47 tag", func() {
			So(lang, ShouldBeIn, []string{"zh-CN", "en-US", "zh", "en", "es-ES", "fr-FR", "de-DE", "ja-JP", "pt-BR"})
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

func TestNormalizeLanguageTag(t *testing.T) {
	Convey("Given the normalizeLanguageTag function", t, func() {
		Convey("When normalizing short codes", func() {
			Convey("zh should normalize to zh-CN", func() {
				So(normalizeLanguageTag("zh"), ShouldEqual, "zh-CN")
			})

			Convey("en should normalize to en-US", func() {
				So(normalizeLanguageTag("en"), ShouldEqual, "en-US")
			})

			Convey("es should normalize to es-ES", func() {
				So(normalizeLanguageTag("es"), ShouldEqual, "es-ES")
			})

			Convey("fr should normalize to fr-FR", func() {
				So(normalizeLanguageTag("fr"), ShouldEqual, "fr-FR")
			})

			Convey("de should normalize to de-DE", func() {
				So(normalizeLanguageTag("de"), ShouldEqual, "de-DE")
			})

			Convey("ja should normalize to ja-JP", func() {
				So(normalizeLanguageTag("ja"), ShouldEqual, "ja-JP")
			})

			Convey("pt should normalize to pt-BR", func() {
				So(normalizeLanguageTag("pt"), ShouldEqual, "pt-BR")
			})
		})

		Convey("When normalizing case", func() {
			Convey("ZH should normalize to zh-CN", func() {
				So(normalizeLanguageTag("ZH"), ShouldEqual, "zh-CN")
			})

			Convey("zh-cn should normalize to zh-CN", func() {
				So(normalizeLanguageTag("zh-cn"), ShouldEqual, "zh-CN")
			})

			Convey("EN-us should normalize to en-US", func() {
				So(normalizeLanguageTag("EN-us"), ShouldEqual, "en-US")
			})
		})

		Convey("When tag is already in BCP 47 format", func() {
			Convey("zh-CN should remain zh-CN", func() {
				So(normalizeLanguageTag("zh-CN"), ShouldEqual, "zh-CN")
			})

			Convey("en-US should remain en-US", func() {
				So(normalizeLanguageTag("en-US"), ShouldEqual, "en-US")
			})
		})

		Convey("When tag is empty", func() {
			So(normalizeLanguageTag(""), ShouldEqual, "")
		})

		Convey("When tag has region variant", func() {
			Convey("zh-TW should normalize to zh-TW", func() {
				So(normalizeLanguageTag("zh-TW"), ShouldEqual, "zh-TW")
			})

			Convey("en-GB should normalize to en-GB", func() {
				So(normalizeLanguageTag("en-GB"), ShouldEqual, "en-GB")
			})
		})
	})
}

func TestValidateLanguageTag(t *testing.T) {
	Convey("Given the validateLanguageTag function", t, func() {
		Convey("When validating valid tags", func() {
			Convey("en should be valid", func() {
				So(validateLanguageTag("en"), ShouldBeNil)
			})

			Convey("zh-CN should be valid", func() {
				So(validateLanguageTag("zh-CN"), ShouldBeNil)
			})

			Convey("es-ES should be valid", func() {
				So(validateLanguageTag("es-ES"), ShouldBeNil)
			})

			Convey("empty string should be valid", func() {
				So(validateLanguageTag(""), ShouldBeNil)
			})
		})

		Convey("When validating invalid separators", func() {
			Convey("zh_CN should be invalid", func() {
				err := validateLanguageTag("zh_CN")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "use '-' as separator")
			})

			Convey("en.US should be invalid", func() {
				err := validateLanguageTag("en.US")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "use '-' as separator")
			})
		})

		Convey("When validating invalid language codes", func() {
			Convey("x should be invalid (too short)", func() {
				err := validateLanguageTag("x")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "must be 2-3 letters")
			})

			Convey("e1 should be invalid (contains digit)", func() {
				err := validateLanguageTag("e1")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "must contain only letters")
			})
		})

		Convey("When validating invalid region codes", func() {
			Convey("en-U should be invalid (too short)", func() {
				err := validateLanguageTag("en-U")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "must be 2 letters or 3 digits")
			})

			Convey("en-USA should be invalid (3 letters)", func() {
				err := validateLanguageTag("en-USA")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "must be 2 letters or 3 digits")
			})
		})

		Convey("When validating too many parts", func() {
			Convey("en-US-variant should be invalid", func() {
				err := validateLanguageTag("en-US-variant")
				So(err, ShouldNotBeNil)
				So(err.Error(), ShouldContainSubstring, "use 'language' or 'language-REGION' format")
			})
		})
	})
}

func TestIsSupportedLanguage(t *testing.T) {
	Convey("Given the isSupportedLanguage function", t, func() {
		Convey("When checking supported languages", func() {
			Convey("en should be supported", func() {
				So(isSupportedLanguage("en"), ShouldBeTrue)
			})

			Convey("zh should be supported", func() {
				So(isSupportedLanguage("zh"), ShouldBeTrue)
			})
		})

		Convey("When checking with region codes", func() {
			Convey("en-US should be supported (matches en)", func() {
				So(isSupportedLanguage("en-US"), ShouldBeTrue)
			})

			Convey("zh-CN should be supported (matches zh)", func() {
				So(isSupportedLanguage("zh-CN"), ShouldBeTrue)
			})

			Convey("zh-TW should be supported (matches zh)", func() {
				So(isSupportedLanguage("zh-TW"), ShouldBeTrue)
			})
		})

		Convey("When checking unsupported languages", func() {
			Convey("ko should not be supported", func() {
				So(isSupportedLanguage("ko"), ShouldBeFalse)
			})

			Convey("ar-SA should not be supported", func() {
				So(isSupportedLanguage("ar-SA"), ShouldBeFalse)
			})

			Convey("empty string should not be supported", func() {
				So(isSupportedLanguage(""), ShouldBeFalse)
			})
		})
	})
}

func TestGetSupportedLanguages(t *testing.T) {
	Convey("Given the GetSupportedLanguages function", t, func() {
		langs := GetSupportedLanguages()

		Convey("It should return at least en and zh", func() {
			So(langs, ShouldContain, "en")
			So(langs, ShouldContain, "zh")
		})

		Convey("It should return non-empty list", func() {
			So(len(langs), ShouldBeGreaterThan, 0)
		})
	})
}
