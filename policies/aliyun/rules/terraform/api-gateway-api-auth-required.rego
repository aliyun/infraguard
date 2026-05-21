package infraguard.rules.terraform.api_gateway_api_auth_required

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "api-gateway-api-auth-required",
	"severity": "medium",
	"name": {
		"en": "API Gateway API Auth Required",
		"zh": "API 网关中配置 API 安全认证",
		"ja": "API ゲートウェイ API 認証が必要",
		"de": "API Gateway API-Authentifizierung erforderlich",
		"es": "Autenticación de API del Gateway de API Requerida",
		"fr": "Authentification API du Gateway API Requise",
		"pt": "Autenticação de API do Gateway de API Obrigatória"
	},
	"description": {
		"en": "Ensures API Gateway APIs have authentication configured.",
		"zh": "确保 API 网关中配置 API 安全认证。",
		"ja": "API ゲートウェイ API に認証が設定されていることを確認します。",
		"de": "Stellt sicher, dass API Gateway APIs Authentifizierung konfiguriert haben.",
		"es": "Garantiza que las APIs del Gateway de API tengan autenticación configurada.",
		"fr": "Garantit que les APIs du Gateway API ont l'authentification configurée.",
		"pt": "Garante que as APIs do Gateway de API tenham autenticação configurada."
	},
	"reason": {
		"en": "Authentication prevents unauthorized access to APIs.",
		"zh": "认证可防止未授权访问 API。",
		"ja": "認証により、API への不正アクセスを防ぎます。",
		"de": "Authentifizierung verhindert unbefugten Zugriff auf APIs.",
		"es": "La autenticación previene el acceso no autorizado a las APIs.",
		"fr": "L'authentification empêche l'accès non autorisé aux APIs.",
		"pt": "A autenticação impede acesso não autorizado às APIs."
	},
	"recommendation": {
		"en": "Enable authentication for all APIs.",
		"zh": "为所有 API 启用认证。",
		"ja": "すべての API で認証を有効にします。",
		"de": "Aktivieren Sie Authentifizierung für alle APIs.",
		"es": "Habilite autenticación para todas las APIs.",
		"fr": "Activez l'authentification pour toutes les APIs.",
		"pt": "Habilite autenticação para todas as APIs."
	},
	"resource_types": ["alicloud_api_gateway_api"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_api_gateway_api")
	tf.get_attribute(resource, "auth_type", "") == "ANONYMOUS"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_api_gateway_api.%s", [name]),
		"violation_path": ["auth_type"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
