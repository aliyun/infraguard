package infraguard.rules.terraform.fc_function_settings_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "fc-function-settings-check",
	"severity": "medium",
	"name": {
		"en": "FC Function Settings Check",
		"zh": "函数计算中函数设置满足参数指定要求",
		"ja": "FC 関数設定チェック",
		"de": "FC-Funktionseinstellungsprüfung",
		"es": "Verificación de Configuración de Función FC",
		"fr": "Vérification des Paramètres de Fonction FC",
		"pt": "Verificação de Configurações de Função FC"
	},
	"description": {
		"en": "FC function settings should meet specified requirements for optimal performance and security.",
		"zh": "函数计算 2.0 中的函数设置满足参数指定的要求，视为合规。",
		"ja": "FC 関数設定は、最適なパフォーマンスとセキュリティのために指定された要件を満たす必要があります。",
		"de": "FC-Funktionseinstellungen sollten die angegebenen Anforderungen für optimale Leistung und Sicherheit erfüllen.",
		"es": "Las configuraciones de función FC deben cumplir con los requisitos especificados para un rendimiento y seguridad óptimos.",
		"fr": "Les paramètres de fonction FC doivent répondre aux exigences spécifiées pour des performances et une sécurité optimales.",
		"pt": "As configurações de função FC devem atender aos requisitos especificados para desempenho e segurança ideais."
	},
	"reason": {
		"en": "The FC function does not have valid settings configured.",
		"zh": "函数计算中的函数设置可能不满足指定要求。",
		"ja": "FC 関数設定が指定された要件を満たしていない可能性があります。",
		"de": "Die FC-Funktionseinstellungen erfüllen möglicherweise nicht die angegebenen Anforderungen.",
		"es": "Las configuraciones de función FC pueden no cumplir con los requisitos especificados.",
		"fr": "Les paramètres de fonction FC peuvent ne pas répondre aux exigences spécifiées.",
		"pt": "As configurações de função FC podem não atender aos requisitos especificados."
	},
	"recommendation": {
		"en": "Configure proper Handler for the function.",
		"zh": "根据组织要求审查和更新函数设置。",
		"ja": "組織の要件に従って関数設定を確認し、更新します。",
		"de": "Überprüfen und aktualisieren Sie die Funktionseinstellungen gemäß den Anforderungen Ihrer Organisation.",
		"es": "Revise y actualice la configuración de la función según los requisitos de su organización.",
		"fr": "Examinez et mettez à jour les paramètres de fonction selon les exigences de votre organisation.",
		"pt": "Revise e atualize as configurações da função de acordo com os requisitos da sua organização."
	},
	"resource_types": ["alicloud_fc_function"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_fc_function")
	handler := tf.get_attribute(resource, "handler", "")
	handler == ""
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_fc_function.%s", [name]),
		"violation_path": ["handler"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
