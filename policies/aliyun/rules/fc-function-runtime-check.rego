package infraguard.rules.aliyun.fc_function_runtime_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:fc-function-runtime-check",
	"name": {
		"en": "FC Function Runtime Check",
		"zh": "FC 未使用废弃的运行时",
	},
	"severity": "high",
	"description": {
		"en": "FC functions should not use deprecated runtimes that may have security vulnerabilities.",
		"zh": "FC 使用的运行时未废弃，则视为合规。截止 2025-04-20，本规则检测废弃版本清单为：nodejs12,nodejs10,nodejs8,dotnetcore2.1,python2.7,nodejs6,nodejs4.4。",
	},
	"reason": {
		"en": "The FC function is using a deprecated runtime that may have security vulnerabilities.",
		"zh": "FC 函数使用了已废弃的运行时，可能存在安全漏洞。",
	},
	"recommendation": {
		"en": "Migrate the function to a supported runtime version. See FC documentation for supported runtimes.",
		"zh": "将函数迁移到支持的运行时版本。请参阅 FC 文档了解支持的运行时。",
	},
	"resource_types": ["ALIYUN::FC::Function"],
}

# Deprecated runtimes as of the specified date (using Set for string key lookup)
deprecated_runtimes := {
	"nodejs12",
	"nodejs10",
	"nodejs8",
	"dotnetcore2.1",
	"python2.7",
	"nodejs6",
	"nodejs4.4",
}

# Deny rule: FC functions must not use deprecated runtimes
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Function")
	runtime := helpers.get_property(resource, "Runtime", "")
	deprecated_runtimes[runtime]
	result := {
		"id": "rule:aliyun:fc-function-runtime-check",
		"resource_id": name,
		"violation_path": ["Properties", "Runtime"],
		"meta": {
			"severity": "high",
			"reason": "The FC function is using a deprecated runtime that may have security vulnerabilities.",
			"recommendation": "Migrate the function to a supported runtime version.",
		},
	}
}
