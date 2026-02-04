package infraguard.rules.aliyun.api_gateway_api_auth_jwt

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "api-gateway-api-auth-jwt",
	"severity": "medium",
	"name": {
		"en": "API Gateway API Auth JWT",
		"zh": "API 网关中 API 安全认证设置为 JWT 方式",
		"ja": "API ゲートウェイ API 認証 JWT",
		"de": "API Gateway API-Authentifizierung JWT",
		"es": "Autenticación JWT de API de API Gateway",
		"fr": "Authentification JWT de l'API API Gateway",
		"pt": "Autenticação JWT da API do API Gateway"
	},
	"description": {
		"en": "Ensures API Gateway APIs use JWT authentication.",
		"zh": "确保 API 网关中的 API 安全认证为 JWT 方式。",
		"ja": "API ゲートウェイ API が JWT 認証を使用することを確認します。",
		"de": "Stellt sicher, dass API Gateway APIs JWT-Authentifizierung verwenden.",
		"es": "Garantiza que las APIs de API Gateway usen autenticación JWT.",
		"fr": "Garantit que les API API Gateway utilisent l'authentification JWT.",
		"pt": "Garante que as APIs do API Gateway usem autenticação JWT."
	},
	"reason": {
		"en": "JWT provides secure authentication for API access.",
		"zh": "JWT 为 API 访问提供安全的认证机制。",
		"ja": "JWT は API アクセスに安全な認証を提供します。",
		"de": "JWT bietet sichere Authentifizierung für API-Zugriff.",
		"es": "JWT proporciona autenticación segura para el acceso a la API.",
		"fr": "JWT fournit une authentification sécurisée pour l'accès à l'API.",
		"pt": "JWT fornece autenticação segura para acesso à API."
	},
	"recommendation": {
		"en": "Configure JWT authentication for APIs.",
		"zh": "为 API 配置 JWT 认证。",
		"ja": "API の JWT 認証を設定します。",
		"de": "Konfigurieren Sie JWT-Authentifizierung für APIs.",
		"es": "Configure la autenticación JWT para las APIs.",
		"fr": "Configurez l'authentification JWT pour les API.",
		"pt": "Configure a autenticação JWT para as APIs."
	},
	"resource_types": ["ALIYUN::ApiGateway::Api"]
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	auth_type := helpers.get_property(resource, "AuthType", "")

	not auth_type == "APPOPENID"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "AuthType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	auth_type := helpers.get_property(resource, "AuthType", "")

	auth_type == "APPOPENID"

	open_id_config := helpers.get_property(resource, "OpenIdConnectConfig", {})
	open_id_api_type := object.get(open_id_config, "OpenIdApiType", "")

	not open_id_api_type == "IDTOKEN"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "OpenIdConnectConfig", "OpenIdApiType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
