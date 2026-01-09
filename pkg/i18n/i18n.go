// Package i18n provides internationalization support.
package i18n

import (
	"embed"
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
		Short            string `yaml:"short"`
		Long             string `yaml:"long"`
		TemplateFlag     string `yaml:"template_flag"`
		PolicyFlag       string `yaml:"policy_flag"`
		InputFlag        string `yaml:"input_flag"`
		FormatFlag       string `yaml:"format_flag"`
		OutputFlag       string `yaml:"output_flag"`
		ReportWritten    string `yaml:"report_written"`
		NoViolations     string `yaml:"no_violations"`
		TotalViolations  string `yaml:"total_violations"`
		FilePrefix       string `yaml:"file_prefix"`
		NoTemplatesFound string `yaml:"no_templates_found"`
		SkippedFile      string `yaml:"skipped_file"`
		FileError        string `yaml:"file_error"`
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
		InvalidFormat                   string `yaml:"invalid_format"`
		InvalidLang                     string `yaml:"invalid_lang"`
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
	} `yaml:"errors"`
}

var (
	currentLang     = "en"
	currentMessages *Messages
	englishMessages *Messages // Fallback
	loadedMessages  = make(map[string]*Messages)
)

func init() {
	// Load English as required fallback
	englishMessages = loadLocale("en")
	currentMessages = englishMessages
}

// loadLocale loads a locale from embedded YAML files.
func loadLocale(lang string) *Messages {
	if cached, ok := loadedMessages[lang]; ok {
		return cached
	}

	data, err := localesFS.ReadFile("locales/" + lang + ".yaml")
	if err != nil {
		return nil
	}

	var msgs Messages
	if err := yaml.Unmarshal(data, &msgs); err != nil {
		return nil
	}

	loadedMessages[lang] = &msgs
	return &msgs
}

// DetectLanguage detects the system language and returns "zh" or "en".
func DetectLanguage() string {
	tag, err := locale.Detect()
	if err == nil {
		lang := tag.String()
		if strings.HasPrefix(lang, "zh") {
			return "zh"
		}
	}
	return "en"
}

// SetLanguage sets the current language.
func SetLanguage(lang string) {
	if lang == "" {
		lang = DetectLanguage()
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
// This is used for generating i18n data for all languages in HTML reports.
func GetSupportedLanguages() []string {
	return []string{"en", "zh"}
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
