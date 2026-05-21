package infraguard.rules.terraform.fc_trigger_http_not_anonymous

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "fc-trigger-http-not-anonymous",
	"severity": "high",
	"name": {
		"en": "FC HTTP Trigger Authentication Check",
		"zh": "函数 HTTP 触发器设置为需要身份验证",
		"ja": "FC HTTP トリガー認証チェック",
		"de": "FC HTTP-Trigger Authentifizierungsprüfung",
		"es": "Verificación de Autenticación del Disparador HTTP FC",
		"fr": "Vérification d'Authentification du Déclencheur HTTP FC",
		"pt": "Verificação de Autenticação do Gatilho HTTP FC"
	},
	"description": {
		"en": "FC HTTP triggers should require authentication to prevent unauthorized access.",
		"zh": "函数 HTTP 触发器配置为需要身份验证，视为合规。",
		"ja": "FC HTTP トリガーは、不正アクセスを防ぐために認証を要求する必要があります。",
		"de": "FC HTTP-Trigger sollten Authentifizierung erfordern, um unbefugten Zugriff zu verhindern.",
		"es": "Los disparadores HTTP FC deben requerir autenticación para prevenir acceso no autorizado.",
		"fr": "Les déclencheurs HTTP FC doivent exiger une authentification pour empêcher l'accès non autorisé.",
		"pt": "Os gatilhos HTTP FC devem exigir autenticação para prevenir acesso não autorizado."
	},
	"reason": {
		"en": "The FC HTTP trigger allows anonymous access, which may expose the function to unauthorized invocations.",
		"zh": "函数 HTTP 触发器允许匿名访问，可能导致未经授权的函数调用。",
		"ja": "FC HTTP トリガーが匿名アクセスを許可しているため、関数が不正な呼び出しにさらされる可能性があります。",
		"de": "Der FC HTTP-Trigger erlaubt anonymen Zugriff, was die Funktion möglicherweise unbefugten Aufrufen aussetzt.",
		"es": "El disparador HTTP FC permite acceso anónimo, lo que puede exponer la función a invocaciones no autorizadas.",
		"fr": "Le déclencheur HTTP FC autorise l'accès anonyme, ce qui peut exposer la fonction à des invocations non autorisées.",
		"pt": "O gatilho HTTP FC permite acesso anônimo, o que pode expor a função a invocações não autorizadas."
	},
	"recommendation": {
		"en": "Configure authentication for the HTTP trigger by setting authType to a value other than anonymous in the config.",
		"zh": "通过在 config 中将 authType 设置为非 anonymous 的值来为 HTTP 触发器配置身份验证。",
		"ja": "適切な認証タイプを設定して、HTTP トリガーの認証を設定します。",
		"de": "Konfigurieren Sie die Authentifizierung für den HTTP-Trigger, indem Sie den entsprechenden Autorisierungstyp festlegen.",
		"es": "Configure la autenticación para el disparador HTTP estableciendo el tipo de autorización apropiado.",
		"fr": "Configurez l'authentification pour le déclencheur HTTP en définissant le type d'autorisation approprié.",
		"pt": "Configure a autenticação para o gatilho HTTP definindo o tipo de autorização apropriado."
	},
	"resource_types": ["alicloud_fc_trigger"],
	"iac_type": "terraform"
}

is_anonymous_http_trigger(resource) if {
	trigger_type := tf.get_attribute(resource, "type", "")
	trigger_type == "http"
	config_str := tf.get_attribute(resource, "config", "")
	not tf.is_unknown(config_str)
	config := json.unmarshal(config_str)
	config.authType == "anonymous"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_fc_trigger")
	is_anonymous_http_trigger(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_fc_trigger.%s", [name]),
		"violation_path": ["config", "authType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
