package infraguard.rules.aliyun.security_api_gateway_api_auth_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-api-gateway-api-auth-required",
    "severity": "high",
    "name": {
        "en": "API Gateway API must configure authentication",
        "zh": "API 网关 API 必须配置认证",
        "ja": "API Gateway API は認証を設定する必要があります",
        "de": "API Gateway API muss Authentifizierung konfigurieren",
        "es": "La API de API Gateway debe configurar autenticación",
        "fr": "L'API API Gateway doit configurer l'authentification",
        "pt": "A API do API Gateway deve configurar autenticação",
    },
    "description": {
        "en": "Checks API Gateway API must configure authentication",
        "zh": "检查API 网关 API 必须配置认证",
        "ja": "API Gateway API は認証を設定する必要がありますことを確認します",
        "de": "Prüft, ob API Gateway API muss Authentifizierung konfigurieren.",
        "es": "Comprueba que la API de API Gateway debe configurar autenticación.",
        "fr": "Vérifie que l'API API Gateway doit configurer l'authentification.",
        "pt": "Verifica se a API do API Gateway deve configurar autenticação.",
    },
    "reason": {
        "en": "API Gateway API must configure authentication is not satisfied.",
        "zh": "API 网关 API 必须配置认证未满足。",
        "ja": "API Gateway API は認証を設定する必要がありますが満たされていません。",
        "de": "API Gateway API muss Authentifizierung konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que la API de API Gateway debe configurar autenticación.",
        "fr": "La condition suivante n'est pas satisfaite : l'API API Gateway doit configurer l'authentification.",
        "pt": "A condição não foi satisfeita: a API do API Gateway deve configurar autenticação.",
    },
    "recommendation": {
        "en": "Configure AuthType on ALIYUN::ApiGateway::Api to satisfy the policy.",
        "zh": "请在 ALIYUN::ApiGateway::Api 上配置 AuthType 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::ApiGateway::Api に AuthType を設定してください。",
        "de": "Konfigurieren Sie AuthType für ALIYUN::ApiGateway::Api, um die Richtlinie zu erfüllen.",
        "es": "Configure AuthType en ALIYUN::ApiGateway::Api para cumplir la política.",
        "fr": "Configurez AuthType sur ALIYUN::ApiGateway::Api pour satisfaire la politique.",
        "pt": "Configure AuthType em ALIYUN::ApiGateway::Api para atender à política.",
    },
    "resource_types": ["ALIYUN::ApiGateway::Api"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ApiGateway::Api")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "AuthType"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.has_property(resource, "AuthType")
}
