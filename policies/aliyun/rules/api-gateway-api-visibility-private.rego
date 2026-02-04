package infraguard.rules.aliyun.api_gateway_api_visibility_private

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "api-gateway-api-visibility-private",
	"name": {
		"en": "API Gateway API Visibility Private",
		"zh": "API 网关中的 API 设置为私有",
		"ja": "API ゲートウェイ API の可視性がプライベート",
		"de": "API-Gateway-API-Sichtbarkeit privat",
		"es": "Visibilidad de API de API Gateway Privada",
		"fr": "Visibilité API de l'API Gateway Privée",
		"pt": "Visibilidade da API do API Gateway Privada"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures API Gateway APIs are set to PRIVATE visibility.",
		"zh": "确保 API 网关中的 API 设置为私有。",
		"ja": "API ゲートウェイの API が PRIVATE 可視性に設定されていることを確認します。",
		"de": "Stellt sicher, dass API-Gateway-APIs auf PRIVATE-Sichtbarkeit gesetzt sind.",
		"es": "Garantiza que las API de API Gateway estén configuradas con visibilidad PRIVADA.",
		"fr": "Garantit que les API de l'API Gateway sont définies sur la visibilité PRIVÉE.",
		"pt": "Garante que as APIs do API Gateway estejam definidas com visibilidade PRIVADA."
	},
	"reason": {
		"en": "Private APIs are only accessible within the VPC, reducing exposure.",
		"zh": "私有 API 只能在 VPC 内访问，减少暴露面。",
		"ja": "プライベート API は VPC 内でのみアクセス可能で、露出を減らします。",
		"de": "Private APIs sind nur innerhalb des VPC zugänglich, was die Exposition reduziert.",
		"es": "Las API privadas solo son accesibles dentro de la VPC, reduciendo la exposición.",
		"fr": "Les API privées ne sont accessibles qu'au sein du VPC, réduisant l'exposition.",
		"pt": "APIs privadas são acessíveis apenas dentro da VPC, reduzindo a exposição."
	},
	"recommendation": {
		"en": "Set API visibility to PRIVATE for internal APIs.",
		"zh": "将内部 API 的可见性设置为私有。",
		"ja": "内部 API の可視性を PRIVATE に設定します。",
		"de": "Setzen Sie die API-Sichtbarkeit für interne APIs auf PRIVATE.",
		"es": "Establezca la visibilidad de la API en PRIVADA para API internas.",
		"fr": "Définissez la visibilité de l'API sur PRIVÉE pour les API internes.",
		"pt": "Defina a visibilidade da API como PRIVADA para APIs internas."
	},
	"resource_types": ["ALIYUN::ApiGateway::Api"],
}

deny contains result if {
	some api_name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
	visibility := helpers.get_property(resource, "Visibility", "")

	visibility == "PUBLIC"

	result := {
		"id": rule_meta.id,
		"resource_id": api_name,
		"violation_path": ["Properties", "Visibility"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
