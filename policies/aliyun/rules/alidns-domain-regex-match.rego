package infraguard.rules.aliyun.alidns_domain_regex_match

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "alidns-domain-regex-match",
	"name": {
		"en": "Alibaba Cloud DNS Domain Names Match Naming Convention",
		"zh": "阿里云解析域名符合命名规范",
		"ja": "Alibaba Cloud DNS ドメイン名が命名規則に一致",
		"de": "Alibaba Cloud DNS-Domänennamen entsprechen Namenskonvention",
		"es": "Los Nombres de Dominio DNS de Alibaba Cloud Coinciden con la Convención de Nomenclatura",
		"fr": "Les Noms de Domaine DNS d'Alibaba Cloud Correspondent à la Convention de Dénomination",
		"pt": "Os Nomes de Domínio DNS da Alibaba Cloud Correspondem à Convenção de Nomenclatura",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that Alibaba Cloud DNS domain names match the specified naming convention regex.",
		"zh": "域名符合参数指定的命名规范正则，视为合规。",
		"ja": "Alibaba Cloud DNS ドメイン名が指定された命名規則の正規表現に一致していることを確認します。",
		"de": "Stellt sicher, dass Alibaba Cloud DNS-Domänennamen dem angegebenen Namenskonventions-Regex entsprechen.",
		"es": "Garantiza que los nombres de dominio DNS de Alibaba Cloud coincidan con la expresión regular de convención de nomenclatura especificada.",
		"fr": "Garantit que les noms de domaine DNS d'Alibaba Cloud correspondent à l'expression régulière de convention de dénomination spécifiée.",
		"pt": "Garante que os nomes de domínio DNS da Alibaba Cloud correspondam à expressão regular de convenção de nomenclatura especificada.",
	},
	"reason": {
		"en": "Domain name does not match the specified naming convention regex.",
		"zh": "域名不符合参数指定的命名规范正则。",
		"ja": "ドメイン名が指定された命名規則の正規表現に一致していません。",
		"de": "Domänenname entspricht nicht dem angegebenen Namenskonventions-Regex.",
		"es": "El nombre de dominio no coincide con la expresión regular de convención de nomenclatura especificada.",
		"fr": "Le nom de domaine ne correspond pas à l'expression régulière de convention de dénomination spécifiée.",
		"pt": "O nome de domínio não corresponde à expressão regular de convenção de nomenclatura especificada.",
	},
	"recommendation": {
		"en": "Rename the domain to match the specified naming convention.",
		"zh": "请修改域名以符合指定的命名规范。",
		"ja": "指定された命名規則に一致するようにドメイン名を変更します。",
		"de": "Benennen Sie die Domäne um, damit sie der angegebenen Namenskonvention entspricht.",
		"es": "Renombre el dominio para que coincida con la convención de nomenclatura especificada.",
		"fr": "Renommez le domaine pour qu'il corresponde à la convention de dénomination spécifiée.",
		"pt": "Renomeie o domínio para corresponder à convenção de nomenclatura especificada.",
	},
	"resource_types": ["ALIYUN::DNS::Domain"],
}

# Default regex pattern for domain names
default_regex_pattern := "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$"

# Get regex pattern from parameters or use default
get_regex_pattern := input.rule_parameters.domain_name_regex_pattern if {
	input.rule_parameters.domain_name_regex_pattern != ""
} else := default_regex_pattern

# Check if domain name matches the regex pattern
domain_name_matches_regex(domain_name, pattern) if {
	regex.match(pattern, domain_name)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::DNS::Domain")

	domain_name := resource.Properties.DomainName
	pattern := get_regex_pattern

	not domain_name_matches_regex(domain_name, pattern)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DomainName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
