// Package i18n provides internationalization support.
package i18n

import (
	"embed"
	"fmt"
	"strings"

	"github.com/Xuanwo/go-locale"
	"gopkg.in/yaml.v3"
)

//go:embed locales/*.yaml
var localesFS embed.FS

// Messages holds all localized strings loaded from YAML.
type Messages struct {
	// Cobra template strings
	Usage              string `yaml:"usage"`
	AvailableCommands  string `yaml:"available_commands"`
	AdditionalCommands string `yaml:"additional_commands"`
	Flags              string `yaml:"flags"`
	GlobalFlags        string `yaml:"global_flags"`
	AdditionalHelp     string `yaml:"additional_help"`
	Aliases            string `yaml:"aliases"`
	Examples           string `yaml:"examples"`

	// Built-in commands
	Completion struct {
		Short string `yaml:"short"`
	} `yaml:"completion"`
	Help struct {
		Short string `yaml:"short"`
		Long  string `yaml:"long"`
	} `yaml:"help"`

	// Version command
	Version struct {
		Short      string `yaml:"short"`
		Long       string `yaml:"long"`
		InfraGuard string `yaml:"infraguard"`
		OPA        string `yaml:"opa"`
	} `yaml:"version"`

	// Root command
	Root struct {
		Short string `yaml:"short"`
		Long  string `yaml:"long"`
	} `yaml:"root"`

	// Policy command
	Policy struct {
		Short string `yaml:"short"`
		Long  string `yaml:"long"`
	} `yaml:"policy"`

	// Policy update command
	PolicyUpdate struct {
		Short       string `yaml:"short"`
		Long        string `yaml:"long"`
		RepoFlag    string `yaml:"repo_flag"`
		VersionFlag string `yaml:"version_flag"`
		Progress    string `yaml:"progress"`
		Success     string `yaml:"success"`
	} `yaml:"policy_update"`

	// Policy get command
	PolicyGet struct {
		Short               string `yaml:"short"`
		Long                string `yaml:"long"`
		NotFoundRule        string `yaml:"not_found_rule"`
		NotFoundPack        string `yaml:"not_found_pack"`
		NoRulesLoaded       string `yaml:"no_rules_loaded"`
		NoPacksLoaded       string `yaml:"no_packs_loaded"`
		RuleDetails         string `yaml:"rule_details"`
		PackDetails         string `yaml:"pack_details"`
		IncludedRules       string `yaml:"included_rules"`
		IncludedRulesFormat string `yaml:"included_rules_format"`
		Name                string `yaml:"name"`
		Description         string `yaml:"description"`
		ResourceTypes       string `yaml:"resource_types"`
		PackID              string `yaml:"pack_id"`
	} `yaml:"policy_get"`

	// Policy list command
	PolicyList struct {
		Short string `yaml:"short"`
		Long  string `yaml:"long"`
		Rules string `yaml:"rules"`
		Packs string `yaml:"packs"`
	} `yaml:"policy_list"`

	// Policy validate command
	PolicyValidate struct {
		Short            string            `yaml:"short"`
		Long             string            `yaml:"long"`
		NoFilesFound     string            `yaml:"no_files_found"`
		Passed           string            `yaml:"passed"`
		Failed           string            `yaml:"failed"`
		Summary          string            `yaml:"summary"`
		SkippedSummary   string            `yaml:"skipped_summary"`
		Suggestion       string            `yaml:"suggestion"`
		FileTypeRule     string            `yaml:"file_type_rule"`
		FileTypePack     string            `yaml:"file_type_pack"`
		FileTypeUnknown  string            `yaml:"file_type_unknown"`
		SkippedPrefix    string            `yaml:"skipped_prefix"`
		ErrorPrefix      string            `yaml:"error_prefix"`
		SuggestionPrefix string            `yaml:"suggestion_prefix"`
		Errors           map[string]string `yaml:"errors"`
	} `yaml:"policy_validate"`

	// Policy format command
	PolicyFormat struct {
		Short             string `yaml:"short"`
		Long              string `yaml:"long"`
		WriteFlag         string `yaml:"write_flag"`
		DiffFlag          string `yaml:"diff_flag"`
		NoFilesFound      string `yaml:"no_files_found"`
		Formatted         string `yaml:"formatted"`
		AlreadyFormatted  string `yaml:"already_formatted"`
		NeedsFormatting   string `yaml:"needs_formatting"`
		SummaryChanged    string `yaml:"summary_changed"`
		SummaryUnchanged  string `yaml:"summary_unchanged"`
		NeedsFormat       string `yaml:"needs_format"`
		ErrorPrefix       string `yaml:"error_prefix"`
		SuccessPrefix     string `yaml:"success_prefix"`
		NeedsFormatPrefix string `yaml:"needs_format_prefix"`
	} `yaml:"policy_format"`

	// Policy clean command
	PolicyClean struct {
		Short        string `yaml:"short"`
		Long         string `yaml:"long"`
		ForceFlag    string `yaml:"force_flag"`
		Confirm      string `yaml:"confirm"`
		Progress     string `yaml:"progress"`
		Success      string `yaml:"success"`
		AlreadyClean string `yaml:"already_clean"`
		Cancelled    string `yaml:"cancelled"`
	} `yaml:"policy_clean"`

	// Update command
	Update struct {
		Short            string `yaml:"short"`
		Long             string `yaml:"long"`
		CheckFlag        string `yaml:"check_flag"`
		ForceFlag        string `yaml:"force_flag"`
		VersionFlag      string `yaml:"version_flag"`
		Checking         string `yaml:"checking"`
		CurrentVersion   string `yaml:"current_version"`
		LatestVersion    string `yaml:"latest_version"`
		AlreadyLatest    string `yaml:"already_latest"`
		UpdateAvailable  string `yaml:"update_available"`
		Downloading      string `yaml:"downloading"`
		DownloadProgress string `yaml:"download_progress"`
		Extracting       string `yaml:"extracting"`
		Installing       string `yaml:"installing"`
		BackupCreated    string `yaml:"backup_created"`
		Success          string `yaml:"success"`
		SuccessWindows   string `yaml:"success_windows"`
		Errors           struct {
			FetchLatest         string `yaml:"fetch_latest"`
			FetchSpecific       string `yaml:"fetch_specific"`
			CompareVersions     string `yaml:"compare_versions"`
			NoUpdateNeeded      string `yaml:"no_update_needed"`
			DownloadFailed      string `yaml:"download_failed"`
			InstallFailed       string `yaml:"install_failed"`
			PermissionDenied    string `yaml:"permission_denied"`
			UnsupportedPlatform string `yaml:"unsupported_platform"`
			NetworkError        string `yaml:"network_error"`
			RateLimit           string `yaml:"rate_limit"`
		} `yaml:"errors"`
	} `yaml:"update"`

	// Config command
	Config struct {
		Short        string `yaml:"short"`
		Long         string `yaml:"long"`
		SetSuccess   string `yaml:"set_success"`
		UnsetSuccess string `yaml:"unset_success"`
		ListFormat   string `yaml:"list_format"`
		Set          struct {
			Short string `yaml:"short"`
			Long  string `yaml:"long"`
		} `yaml:"set"`
		Get struct {
			Short string `yaml:"short"`
			Long  string `yaml:"long"`
		} `yaml:"get"`
		Unset struct {
			Short string `yaml:"short"`
			Long  string `yaml:"long"`
		} `yaml:"unset"`
		List struct {
			Short string `yaml:"short"`
			Long  string `yaml:"long"`
		} `yaml:"list"`
		Errors struct {
			UnknownKey   string `yaml:"unknown_key"`
			InvalidValue string `yaml:"invalid_value"`
		} `yaml:"errors"`
	} `yaml:"config"`

	// Scan command
	Scan struct {
		Short                string `yaml:"short"`
		Long                 string `yaml:"long"`
		TemplateFlag         string `yaml:"template_flag"`
		PolicyFlag           string `yaml:"policy_flag"`
		InputFlag            string `yaml:"input_flag"`
		FormatFlag           string `yaml:"format_flag"`
		OutputFlag           string `yaml:"output_flag"`
		ModeFlag             string `yaml:"mode_flag"`
		ReportWritten        string `yaml:"report_written"`
		NoViolations         string `yaml:"no_violations"`
		TotalViolations      string `yaml:"total_violations"`
		FilePrefix           string `yaml:"file_prefix"`
		NoTemplatesFound     string `yaml:"no_templates_found"`
		NoTemplatesProcessed string `yaml:"no_templates_processed"`
		SkippedFile          string `yaml:"skipped_file"`
		FileError            string `yaml:"file_error"`
		StatusCode           string `yaml:"status_code"`
		Code                 string `yaml:"code"`
		Message              string `yaml:"message"`
		RequestID            string `yaml:"request_id"`
		CallingPreviewStack  string `yaml:"calling_preview_stack"`
	} `yaml:"scan"`

	// Report
	Report struct {
		Title                 string `yaml:"title"`
		TotalViolations       string `yaml:"total_violations"`
		PassedRules           string `yaml:"passed_rules"`
		FailedRules           string `yaml:"failed_rules"`
		Severity              string `yaml:"severity"`
		RuleID                string `yaml:"rule_id"`
		Resource              string `yaml:"resource"`
		Location              string `yaml:"location"`
		Line                  string `yaml:"line"`
		Reason                string `yaml:"reason"`
		Recommendation        string `yaml:"recommendation"`
		Results               string `yaml:"results"`
		Count                 string `yaml:"count"`
		Type                  string `yaml:"type"`
		Breakdown             string `yaml:"breakdown"`
		Passed                string `yaml:"passed"`
		Failed                string `yaml:"failed"`
		Total                 string `yaml:"total"`
		NoViolationsPrefix    string `yaml:"no_violations_prefix"`
		ViolationHeaderFormat string `yaml:"violation_header_format"`
		LocationFormat        string `yaml:"location_format"`
		LineHighlightPrefix   string `yaml:"line_highlight_prefix"`
		LineNormalPrefix      string `yaml:"line_normal_prefix"`
		MetadataPrefix        string `yaml:"metadata_prefix"`
		MetadataSeparator     string `yaml:"metadata_separator"`
		SummaryPrefix         string `yaml:"summary_prefix"`
		SummarySeparator      string `yaml:"summary_separator"`
	} `yaml:"report"`

	// Severity levels
	Severity struct {
		High   string `yaml:"high"`
		Medium string `yaml:"medium"`
		Low    string `yaml:"low"`
	} `yaml:"severity"`

	// Global flags
	LangFlag string `yaml:"lang_flag"`

	// Error messages
	Errors struct {
		InvalidFormat string `yaml:"invalid_format"`
		InvalidLang   string `yaml:"invalid_lang"`
		InvalidMode   string `yaml:"invalid_mode"`

		// Language tag validation errors
		InvalidLangTagSeparator string `yaml:"invalid_lang_tag_separator"`
		InvalidLangTagFormat    string `yaml:"invalid_lang_tag_format"`
		InvalidLangCodeLength   string `yaml:"invalid_lang_code_length"`
		InvalidLangCodeChars    string `yaml:"invalid_lang_code_chars"`
		InvalidRegionCodeLength string `yaml:"invalid_region_code_length"`
		InvalidRegionCodeFormat string `yaml:"invalid_region_code_format"`

		PolicyDir                       string `yaml:"policy_dir"`
		PolicyDirHint                   string `yaml:"policy_dir_hint"`
		LoadTemplate                    string `yaml:"load_template"`
		EvaluatePolicies                string `yaml:"evaluate_policies"`
		RenderReport                    string `yaml:"render_report"`
		UpdatePolicies                  string `yaml:"update_policies"`
		InvalidPolicySpec               string `yaml:"invalid_policy_spec"`
		NoRegoFiles                     string `yaml:"no_rego_files"`
		NoRegoFilesInDir                string `yaml:"no_rego_files_in_dir"`
		PolicyNotFound                  string `yaml:"policy_not_found"`
		PolicyPatternNoMatch            string `yaml:"policy_pattern_no_match"`
		FileNotFound                    string `yaml:"file_not_found"`
		DirNotFound                     string `yaml:"dir_not_found"`
		PathNotFound                    string `yaml:"path_not_found"`
		PolicyFileExtension             string `yaml:"policy_file_extension"`
		InvalidROSTemplate              string `yaml:"invalid_ros_template"`
		InvalidInput                    string `yaml:"invalid_input"`
		ParseInputFile                  string `yaml:"parse_input_file"`
		ReadInputFile                   string `yaml:"read_input_file"`
		UnableToDetermineHomeDir        string `yaml:"unable_to_determine_home_dir"`
		AliyunConfigNotFound            string `yaml:"aliyun_config_not_found"`
		ReadAliyunConfig                string `yaml:"read_aliyun_config"`
		ParseAliyunConfig               string `yaml:"parse_aliyun_config"`
		ProfileNotFound                 string `yaml:"profile_not_found"`
		InvalidAccessKey                string `yaml:"invalid_access_key"`
		GetHomeDirectory                string `yaml:"get_home_directory"`
		ReadConfigFile                  string `yaml:"read_config_file"`
		ParseConfigFile                 string `yaml:"parse_config_file"`
		CreateConfigDir                 string `yaml:"create_config_dir"`
		MarshalConfig                   string `yaml:"marshal_config"`
		WriteConfigFile                 string `yaml:"write_config_file"`
		ReadTemplateFile                string `yaml:"read_template_file"`
		ParseJSONTemplate               string `yaml:"parse_json_template"`
		ParseYAMLTemplate               string `yaml:"parse_yaml_template"`
		PathDoesNotExist                string `yaml:"path_does_not_exist"`
		FileMustBeRego                  string `yaml:"file_must_be_rego"`
		ReadFile                        string `yaml:"read_file"`
		FormatFile                      string `yaml:"format_file"`
		WriteFile                       string `yaml:"write_file"`
		NoPolicyPaths                   string `yaml:"no_policy_paths"`
		DiscoverRegoFiles               string `yaml:"discover_rego_files"`
		NoRegoFilesInPaths              string `yaml:"no_rego_files_in_paths"`
		ReadRegoFile                    string `yaml:"read_rego_file"`
		PrepareRegoQuery                string `yaml:"prepare_rego_query"`
		EvaluatePoliciesInternal        string `yaml:"evaluate_policies_internal"`
		ParameterTypeMismatch           string `yaml:"parameter_type_mismatch"`
		UndefinedParameters             string `yaml:"undefined_parameters"`
		NoParametersDefined             string `yaml:"no_parameters_defined"`
		UnknownHelpTopic                string `yaml:"unknown_help_topic"`
		ReadFileError                   string `yaml:"read_file_error"`
		SyntaxErrorWithDetail           string `yaml:"syntax_error_with_detail"`
		RuleInvalidSeverityWithValue    string `yaml:"rule_invalid_severity_with_value"`
		DenyRuleEvaluationError         string `yaml:"deny_rule_evaluation_error"`
		DenyResultFieldRequired         string `yaml:"deny_result_field_required"`
		AddFieldToDenyResult            string `yaml:"add_field_to_deny_result"`
		FieldMustBeStringOrDict         string `yaml:"field_must_be_string_or_dict"`
		ChangeFieldToI18nFormat         string `yaml:"change_field_to_i18n_format"`
		RuleMetaFieldMustBeStringOrDict string `yaml:"rule_meta_field_must_be_string_or_dict"`
		InvalidROSTemplateVersion       string `yaml:"invalid_ros_template_version"`
		ParseHTMLTemplate               string `yaml:"parse_html_template"`
		MarshalI18nData                 string `yaml:"marshal_i18n_data"`
		ParseRuleMeta                   string `yaml:"parse_rule_meta"`
		ParsePackMeta                   string `yaml:"parse_pack_meta"`
		NoPoliciesFound                 string `yaml:"no_policies_found"`
		ReadEmbeddedPoliciesRoot        string `yaml:"read_embedded_policies_root"`
		LoadEmbeddedRulesForProvider    string `yaml:"load_embedded_rules_for_provider"`
		LoadEmbeddedPacksForProvider    string `yaml:"load_embedded_packs_for_provider"`
		ReadPolicyDirectory             string `yaml:"read_policy_directory"`
		DiscoverRulesForProvider        string `yaml:"discover_rules_for_provider"`
		DiscoverPacksForProvider        string `yaml:"discover_packs_for_provider"`
		CleanPolicyDirectory            string `yaml:"clean_policy_directory"`
		CreatePolicyDirectory           string `yaml:"create_policy_directory"`
		DownloadPolicies                string `yaml:"download_policies"`
		PolicyPathDoesNotExist          string `yaml:"policy_path_does_not_exist"`
		NoRegoFilesInPolicyDirectory    string `yaml:"no_rego_files_in_policy_directory"`

		// Preview mode errors
		PreviewOnlyROSSupported string `yaml:"preview_only_ros_supported"`
		PreviewUnsupportedMode  string `yaml:"preview_unsupported_mode"`

		// ROS provider errors
		ROSFailedLoadTemplate      string `yaml:"ros_failed_load_template"`
		ROSInvalidTemplate         string `yaml:"ros_invalid_template"`
		ROSInvalidParameters       string `yaml:"ros_invalid_parameters"`
		ROSFailedResolveParameters string `yaml:"ros_failed_resolve_parameters"`
		ROSFailedLoadCredentials   string `yaml:"ros_failed_load_credentials"`
		ROSInvalidCredentials      string `yaml:"ros_invalid_credentials"`
		ROSFailedCreateClient      string `yaml:"ros_failed_create_client"`
		ROSFailedMarshalTemplate   string `yaml:"ros_failed_marshal_template"`
		ROSFailedCallAPI           string `yaml:"ros_failed_call_api"`
		ROSFailedConvertResponse   string `yaml:"ros_failed_convert_response"`
		ROSClientNil               string `yaml:"ros_client_nil"`
		ROSFailedMarshalParameter  string `yaml:"ros_failed_marshal_parameter"`
		ROSEmptyResponse           string `yaml:"ros_empty_response"`
		ROSNoStackInfo             string `yaml:"ros_no_stack_info"`
		ROSInvalidPreviewResponse  string `yaml:"ros_invalid_preview_response"`

		// ROS auth errors
		ROSAuthInvalidAccessKey        string `yaml:"ros_auth_invalid_access_key"`
		ROSAuthSignatureMismatch       string `yaml:"ros_auth_signature_mismatch"`
		ROSAuthInsufficientPermissions string `yaml:"ros_auth_insufficient_permissions"`
		ROSRateLimit                   string `yaml:"ros_rate_limit"`
		ROSServiceUnavailable          string `yaml:"ros_service_unavailable"`
		ROSTemplateValidationFailed    string `yaml:"ros_template_validation_failed"`
		ROSNetworkError                string `yaml:"ros_network_error"`
		ROSAPIError                    string `yaml:"ros_api_error"`

		// ROS credentials errors
		ROSFailedGetHomeDir        string `yaml:"ros_failed_get_home_dir"`
		ROSCredentialsNotFound     string `yaml:"ros_credentials_not_found"`
		ROSFailedReadConfig        string `yaml:"ros_failed_read_config"`
		ROSFailedParseConfig       string `yaml:"ros_failed_parse_config"`
		ROSNoValidProfile          string `yaml:"ros_no_valid_profile"`
		ROSAccessKeyIDEmpty        string `yaml:"ros_access_key_id_empty"`
		ROSAccessKeySecretEmpty    string `yaml:"ros_access_key_secret_empty"`
		ROSAccessKeyIDRequired     string `yaml:"ros_access_key_id_required"`
		ROSAccessKeySecretRequired string `yaml:"ros_access_key_secret_required"`
		ROSInvalidAccessKeyFormat  string `yaml:"ros_invalid_access_key_format"`
	} `yaml:"errors"`
}

var (
	currentLang     = "en"
	currentMessages *Messages
	englishMessages *Messages // Fallback
	loadedMessages  = make(map[string]*Messages)
)

// LanguageOrder defines the standard order for displaying languages in i18n dictionaries.
// This order is used for formatting policy files to maintain consistency.
var LanguageOrder = []string{"en", "zh", "ja", "de", "es", "fr", "pt"}

// GetLanguageOrderMap returns a map of language code to its display order.
// Lower numbers appear first in sorted output.
func GetLanguageOrderMap() map[string]int {
	langOrderMap := make(map[string]int)
	for i, lang := range LanguageOrder {
		langOrderMap[lang] = i
	}
	return langOrderMap
}

func init() {
	// Load English as required fallback
	englishMessages = loadLocale("en")
	currentMessages = englishMessages
}

// normalizeLanguageTag normalizes a language tag to BCP 47 format.
// It supports two-level normalization:
// 1. Short code mapping: zh -> zh-CN, en -> en-US, etc.
// 2. Language prefix matching: zh-TW -> zh (uses zh translations)
func normalizeLanguageTag(tag string) string {
	if tag == "" {
		return ""
	}

	// Normalize case: language code lowercase, region code uppercase
	tag = strings.ToLower(tag)
	parts := strings.Split(tag, "-")
	if len(parts) == 2 {
		tag = parts[0] + "-" + strings.ToUpper(parts[1])
	} else if len(parts) == 1 {
		tag = parts[0]
	}

	// Level 1: Short code to BCP 47 mapping
	shortToFull := map[string]string{
		"zh": "zh-CN",
		"en": "en-US",
		"es": "es-ES",
		"fr": "fr-FR",
		"de": "de-DE",
		"ja": "ja-JP",
		"pt": "pt-BR",
	}

	if full, ok := shortToFull[tag]; ok {
		return full
	}

	// If already in full format or has region code, return as-is
	if len(parts) == 2 {
		return tag
	}

	return tag
}

// validateLanguageTag validates the format of a language tag.
// Returns an error if the tag contains invalid characters or format.
// Valid formats: "language" or "language-REGION"
func validateLanguageTag(tag string) error {
	if tag == "" {
		return nil
	}

	msg := Msg()

	// Check for invalid separators
	if strings.Contains(tag, "_") || strings.Contains(tag, ".") {
		return fmt.Errorf(msg.Errors.InvalidLangTagSeparator, tag)
	}

	parts := strings.Split(tag, "-")
	if len(parts) > 2 {
		return fmt.Errorf(msg.Errors.InvalidLangTagFormat, tag)
	}

	// Validate language code (2-3 lowercase letters)
	langCode := strings.ToLower(parts[0])
	if len(langCode) < 2 || len(langCode) > 3 {
		return fmt.Errorf(msg.Errors.InvalidLangCodeLength, parts[0])
	}
	for _, c := range langCode {
		if c < 'a' || c > 'z' {
			return fmt.Errorf(msg.Errors.InvalidLangCodeChars, parts[0])
		}
	}

	// Validate region code if present (2 uppercase letters or 3 digits)
	if len(parts) == 2 {
		region := strings.ToUpper(parts[1])
		if len(region) != 2 && len(region) != 3 {
			return fmt.Errorf(msg.Errors.InvalidRegionCodeLength, parts[1])
		}

		if len(region) == 2 {
			for _, c := range region {
				if c < 'A' || c > 'Z' {
					return fmt.Errorf(msg.Errors.InvalidRegionCodeFormat, parts[1])
				}
			}
		} else if len(region) == 3 {
			isAllDigits := true
			for _, c := range region {
				if c < '0' || c > '9' {
					isAllDigits = false
					break
				}
			}
			if !isAllDigits {
				return fmt.Errorf(msg.Errors.InvalidRegionCodeLength, parts[1])
			}
		}
	}

	return nil
}

// isSupportedLanguage checks if a language tag is supported.
// It checks both the full tag and the language code prefix.
func isSupportedLanguage(tag string) bool {
	if tag == "" {
		return false
	}

	supported := GetSupportedLanguages()

	// Check exact match first
	for _, lang := range supported {
		if lang == tag {
			return true
		}
	}

	// Check language prefix match (e.g., zh-TW matches zh)
	parts := strings.Split(tag, "-")
	if len(parts) == 2 {
		langCode := parts[0]
		for _, lang := range supported {
			if lang == langCode {
				return true
			}
		}
	}

	return false
}

// loadLocale loads a locale from embedded YAML files.
// Supports BCP 47 tags with fallback:
// 1. Try full tag (e.g., "zh-CN.yaml")
// 2. Try language code (e.g., "zh.yaml")
// 3. Try language prefix for region variants (e.g., "zh-TW" -> "zh.yaml")
func loadLocale(lang string) *Messages {
	if cached, ok := loadedMessages[lang]; ok {
		return cached
	}

	// Try to load the exact tag first
	data, err := localesFS.ReadFile("locales/" + lang + ".yaml")
	if err != nil {
		// If full tag not found, try language code prefix
		parts := strings.Split(lang, "-")
		if len(parts) == 2 {
			langCode := parts[0]
			data, err = localesFS.ReadFile("locales/" + langCode + ".yaml")
			if err != nil {
				return nil
			}
		} else {
			return nil
		}
	}

	var msgs Messages
	if err := yaml.Unmarshal(data, &msgs); err != nil {
		return nil
	}

	loadedMessages[lang] = &msgs
	return &msgs
}

// DetectLanguage detects the system language and returns a BCP 47 language tag.
// Supports: en, zh, es, fr, de, ja, pt
// Returns normalized BCP 47 tag (e.g., "zh-CN", "en-US")
func DetectLanguage() string {
	tag, err := locale.Detect()
	if err == nil {
		lang := tag.String()
		// Normalize to BCP 47 format
		normalized := normalizeLanguageTag(lang)
		if isSupportedLanguage(normalized) {
			return normalized
		}

		// Try language prefix if full tag not supported
		parts := strings.Split(lang, "_")
		if len(parts) > 0 {
			langCode := strings.ToLower(parts[0])
			normalized = normalizeLanguageTag(langCode)
			if isSupportedLanguage(normalized) {
				return normalized
			}
		}
	}
	return "en-US" // Default to US English
}

// SetLanguage sets the current language.
// If lang is empty, it auto-detects the system language.
// The language tag is normalized to BCP 47 format before setting.
func SetLanguage(lang string) {
	if lang == "" {
		lang = DetectLanguage()
	} else {
		// Normalize the language tag
		lang = normalizeLanguageTag(lang)
	}

	msgs := loadLocale(lang)
	if msgs != nil {
		currentLang = lang
		currentMessages = msgs
	}
}

// GetLanguage returns the current language.
func GetLanguage() string {
	return currentLang
}

// Msg returns the current messages with fallback to English.
func Msg() *Messages {
	return currentMessages
}

// GetMessages returns messages for a specific language.
// Falls back to English if the language is not found.
func GetMessages(lang string) *Messages {
	msgs := loadLocale(lang)
	if msgs != nil {
		return msgs
	}
	return englishMessages
}

// Get returns a message with fallback to English if not found.
// This is used for messages that might be missing in non-English locales.
func Get(getter func(*Messages) string) string {
	if currentMessages != nil {
		if val := getter(currentMessages); val != "" {
			return val
		}
	}
	if englishMessages != nil {
		return getter(englishMessages)
	}
	return ""
}

// Init initializes i18n with auto-detected language.
func Init() {
	SetLanguage(DetectLanguage())
}

// GetSupportedLanguages returns a list of all supported language codes.
// This is dynamically read from the locales directory.
func GetSupportedLanguages() []string {
	entries, err := localesFS.ReadDir("locales")
	if err != nil {
		// Fallback to known languages if reading fails
		return []string{"en", "zh"}
	}

	var langs []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			lang := strings.TrimSuffix(entry.Name(), ".yaml")
			langs = append(langs, lang)
		}
	}

	// Ensure we have at least English as fallback
	if len(langs) == 0 {
		return []string{"en"}
	}

	return langs
}

// FormatMessage formats a message based on language.
// Supports both String and Map formats for i18n in policy files.
func FormatMessage(raw interface{}, lang string) string {
	switch v := raw.(type) {
	case string:
		return v
	case map[string]interface{}:
		if val, ok := v[lang]; ok {
			if s, ok := val.(string); ok {
				return s
			}
		}
		if val, ok := v["en"]; ok {
			if s, ok := val.(string); ok {
				return s
			}
		}
		return ""
	case map[string]string:
		if val, ok := v[lang]; ok {
			return val
		}
		if val, ok := v["en"]; ok {
			return val
		}
		return ""
	default:
		return "Invalid Format"
	}
}
