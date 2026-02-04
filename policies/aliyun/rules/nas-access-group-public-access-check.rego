package infraguard.rules.aliyun.nas_access_group_public_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "nas-access-group-public-access-check",
	"name": {
		"en": "NAS Access Group IP Restriction",
		"zh": "NAS 权限组禁用公网授权",
		"ja": "NAS アクセスグループ IP 制限",
		"de": "NAS-Zugriffsgruppe IP-Beschränkung",
		"es": "Restricción de IP del Grupo de Acceso NAS",
		"fr": "Restriction IP du Groupe d'Accès NAS",
		"pt": "Restrição de IP do Grupo de Acesso NAS",
	},
	"severity": "high",
	"description": {
		"en": "Ensures NAS access rules do not allow 0.0.0.0/0.",
		"zh": "确保 NAS 权限规则不允许 0.0.0.0/0。",
		"ja": "NAS アクセスルールが 0.0.0.0/0 を許可しないことを確認します。",
		"de": "Stellt sicher, dass NAS-Zugriffsregeln 0.0.0.0/0 nicht erlauben.",
		"es": "Garantiza que las reglas de acceso NAS no permitan 0.0.0.0/0.",
		"fr": "Garantit que les règles d'accès NAS n'autorisent pas 0.0.0.0/0.",
		"pt": "Garante que as regras de acesso NAS não permitam 0.0.0.0/0.",
	},
	"reason": {
		"en": "An open NAS access rule can lead to unauthorized data access over the internet.",
		"zh": "开放的 NAS 权限规则可能导致互联网上的非授权数据访问。",
		"ja": "オープンな NAS アクセスルールにより、インターネット経由での不正なデータアクセスが発生する可能性があります。",
		"de": "Eine offene NAS-Zugriffsregel kann zu unbefugtem Datenzugriff über das Internet führen.",
		"es": "Una regla de acceso NAS abierta puede llevar a acceso no autorizado a datos a través de Internet.",
		"fr": "Une règle d'accès NAS ouverte peut entraîner un accès non autorisé aux données via Internet.",
		"pt": "Uma regra de acesso NAS aberta pode levar a acesso não autorizado a dados pela Internet.",
	},
	"recommendation": {
		"en": "Restrict NAS access rules to specific trusted VPC IP ranges.",
		"zh": "将 NAS 权限规则限制在特定的可信 VPC IP 范围内。",
		"ja": "NAS アクセスルールを特定の信頼できる VPC IP 範囲に制限します。",
		"de": "Beschränken Sie NAS-Zugriffsregeln auf spezifische vertrauenswürdige VPC-IP-Bereiche.",
		"es": "Restrinja las reglas de acceso NAS a rangos de IP VPC específicos de confianza.",
		"fr": "Restreignez les règles d'accès NAS à des plages d'IP VPC spécifiques de confiance.",
		"pt": "Restrinja as regras de acesso NAS a intervalos de IP VPC específicos confiáveis.",
	},
	"resource_types": ["ALIYUN::NAS::AccessRule"],
}

is_compliant(resource) if {
	ip := helpers.get_property(resource, "SourceCidrIp", "")
	not helpers.is_public_cidr(ip)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAS::AccessRule")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SourceCidrIp"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
