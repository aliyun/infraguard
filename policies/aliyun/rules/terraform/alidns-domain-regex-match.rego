package infraguard.rules.terraform.alidns_domain_regex_match

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "alidns-domain-regex-match",
	"severity": "medium",
	"name": {
		"en": "Alibaba Cloud DNS Domain Names Match Naming Convention",
		"zh": "阿里云解析域名符合命名规范",
		"ja": "Alibaba Cloud DNS ドメイン名が命名規則に一致",
		"de": "Alibaba Cloud DNS-Domänennamen entsprechen Namenskonvention",
		"es": "Los Nombres de Dominio DNS de Alibaba Cloud Coinciden con la Convención de Nomenclatura",
		"fr": "Les Noms de Domaine DNS d'Alibaba Cloud Correspondent à la Convention de Dénomination",
		"pt": "Os Nomes de Domínio DNS da Alibaba Cloud Correspondem à Convenção de Nomenclatura"
	},
	"description": {
		"en": "Ensures that Alibaba Cloud DNS domain names match the specified naming convention regex.",
		"zh": "域名符合参数指定的命名规范正则，视为合规。",
		"ja": "Alibaba Cloud DNS ドメイン名が指定された命名規則の正規表現に一致していることを確認します。",
		"de": "Stellt sicher, dass Alibaba Cloud DNS-Domänennamen dem angegebenen Namenskonventions-Regex entsprechen.",
		"es": "Garantiza que los nombres de dominio DNS de Alibaba Cloud coincidan con la expresión regular de convención de nomenclatura especificada.",
		"fr": "Garantit que les noms de domaine DNS d'Alibaba Cloud correspondent à l'expression régulière de convention de dénomination spécifiée.",
		"pt": "Garante que os nomes de domínio DNS da Alibaba Cloud correspondam à expressão regular de convenção de nomenclatura especificada."
	},
	"reason": {
		"en": "Domain name does not match the specified naming convention regex.",
		"zh": "域名不符合参数指定的命名规范正则。",
		"ja": "ドメイン名が指定された命名規則の正規表現に一致していません。",
		"de": "Domänenname entspricht nicht dem angegebenen Namenskonventions-Regex.",
		"es": "El nombre de dominio no coincide con la expresión regular de convención de nomenclatura especificada.",
		"fr": "Le nom de domaine ne correspond pas à l'expression régulière de convention de dénomination spécifiée.",
		"pt": "O nome de domínio não corresponde à expressão regular de convenção de nomenclatura especificada."
	},
	"recommendation": {
		"en": "Rename the domain to match the specified naming convention.",
		"zh": "请修改域名以符合指定的命名规范。",
		"ja": "指定された命名規則に一致するようにドメイン名を変更します。",
		"de": "Benennen Sie die Domäne um, damit sie der angegebenen Namenskonvention entspricht.",
		"es": "Renombre el dominio para que coincida con la convención de nomenclatura especificada.",
		"fr": "Renommez le domaine pour qu'il corresponde à la convention de dénomination spécifiée.",
		"pt": "Renomeie o domínio para corresponder à convenção de nomenclatura especificada."
	},
	"resource_types": ["alicloud_alidns_domain"],
	"iac_type": "terraform"
}

default_regex_pattern := "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$"

get_regex_pattern := pattern if {
	params := object.get(input, "rule_parameters", {})
	pattern := object.get(params, "domain_name_regex_pattern", "")
	pattern != ""
} else := default_regex_pattern

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_alidns_domain")
	domain_name := tf.get_attribute(resource, "domain_name", "")
	not tf.is_unknown(domain_name)
	not regex.match(get_regex_pattern, domain_name)

	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_alidns_domain.%s", [name]),
		"violation_path": ["domain_name"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
