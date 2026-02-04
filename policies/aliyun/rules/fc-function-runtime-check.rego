package infraguard.rules.aliyun.fc_function_runtime_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-function-runtime-check",
	"name": {
		"en": "FC Function Runtime Check",
		"zh": "FC 未使用废弃的运行时",
		"ja": "FC 関数ランタイムチェック",
		"de": "FC-Funktionslaufzeitprüfung",
		"es": "Verificación de Runtime de Función FC",
		"fr": "Vérification du Runtime de Fonction FC",
		"pt": "Verificação de Runtime de Função FC",
	},
	"severity": "high",
	"description": {
		"en": "FC functions should not use deprecated runtimes that may have security vulnerabilities.",
		"zh": "FC 使用的运行时未废弃，则视为合规。截止 2025-04-20，本规则检测废弃版本清单为：nodejs12,nodejs10,nodejs8,dotnetcore2.1,python2.7,nodejs6,nodejs4.4。",
		"ja": "FC 関数は、セキュリティの脆弱性がある可能性のある非推奨ランタイムを使用すべきではありません。",
		"de": "FC-Funktionen sollten keine veralteten Laufzeiten verwenden, die Sicherheitslücken haben können.",
		"es": "Las funciones FC no deben usar runtimes deprecados que puedan tener vulnerabilidades de seguridad.",
		"fr": "Les fonctions FC ne doivent pas utiliser de runtimes dépréciés qui peuvent avoir des vulnérabilités de sécurité.",
		"pt": "As funções FC não devem usar runtimes depreciados que possam ter vulnerabilidades de segurança.",
	},
	"reason": {
		"en": "The FC function is using a deprecated runtime that may have security vulnerabilities.",
		"zh": "FC 函数使用了已废弃的运行时，可能存在安全漏洞。",
		"ja": "FC 関数がセキュリティの脆弱性がある可能性のある非推奨ランタイムを使用しています。",
		"de": "Die FC-Funktion verwendet eine veraltete Laufzeit, die Sicherheitslücken haben kann.",
		"es": "La función FC está usando un runtime deprecado que puede tener vulnerabilidades de seguridad.",
		"fr": "La fonction FC utilise un runtime déprécié qui peut avoir des vulnérabilités de sécurité.",
		"pt": "A função FC está usando um runtime depreciado que pode ter vulnerabilidades de segurança.",
	},
	"recommendation": {
		"en": "Migrate the function to a supported runtime version. See FC documentation for supported runtimes.",
		"zh": "将函数迁移到支持的运行时版本。请参阅 FC 文档了解支持的运行时。",
		"ja": "関数をサポートされているランタイムバージョンに移行します。サポートされているランタイムについては、FC ドキュメントを参照してください。",
		"de": "Migrieren Sie die Funktion auf eine unterstützte Laufzeitversion. Siehe FC-Dokumentation für unterstützte Laufzeiten.",
		"es": "Migre la función a una versión de runtime compatible. Consulte la documentación de FC para ver los runtimes compatibles.",
		"fr": "Migrez la fonction vers une version de runtime prise en charge. Consultez la documentation FC pour les runtimes pris en charge.",
		"pt": "Migre a função para uma versão de runtime suportada. Consulte a documentação do FC para runtimes suportados.",
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
		"id": "fc-function-runtime-check",
		"resource_id": name,
		"violation_path": ["Properties", "Runtime"],
		"meta": {
			"severity": "high",
			"reason": "The FC function is using a deprecated runtime that may have security vulnerabilities.",
			"recommendation": "Migrate the function to a supported runtime version.",
		},
	}
}
