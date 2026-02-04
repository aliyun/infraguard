package infraguard.rules.aliyun.slb_acl_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "slb-acl-public-access-check",
	"severity": "high",
	"name": {
		"en": "SLB ACL Public Access Check",
		"zh": "CLB 访问控制列表不配置所有地址段",
		"ja": "SLB ACL のパブリックアクセスチェック",
		"de": "SLB ACL öffentlicher Zugriff-Prüfung",
		"es": "Verificación de Acceso Público de ACL de SLB",
		"fr": "Vérification d'Accès Public ACL SLB",
		"pt": "Verificação de Acesso Público de ACL SLB"
	},
	"description": {
		"en": "Ensures that SLB ACLs do not contain 0.0.0.0/0 to prevent unrestricted public access.",
		"zh": "确保 CLB 访问控制列表中不包含 0.0.0.0/0，以防止无限制的公网访问。",
		"ja": "SLB ACL に 0.0.0.0/0 が含まれていないことを確認し、無制限のパブリックアクセスを防ぎます。",
		"de": "Stellt sicher, dass SLB ACLs 0.0.0.0/0 nicht enthalten, um uneingeschränkten öffentlichen Zugriff zu verhindern.",
		"es": "Garantiza que las ACL de SLB no contengan 0.0.0.0/0 para prevenir acceso público sin restricciones.",
		"fr": "Garantit que les ACL SLB ne contiennent pas 0.0.0.0/0 pour empêcher l'accès public sans restriction.",
		"pt": "Garante que as ACLs SLB não contenham 0.0.0.0/0 para prevenir acesso público sem restrições."
	},
	"reason": {
		"en": "Allowing 0.0.0.0/0 in an ACL bypasses the security benefits of access control, potentially exposing services to attacks.",
		"zh": "在 ACL 中允许 0.0.0.0/0 会绕过访问控制的安全保障，使服务可能遭受攻击。",
		"ja": "ACL で 0.0.0.0/0 を許可すると、アクセス制御のセキュリティ上の利点が回避され、サービスが攻撃にさらされる可能性があります。",
		"de": "Das Zulassen von 0.0.0.0/0 in einer ACL umgeht die Sicherheitsvorteile der Zugriffskontrolle und kann Dienste Angriffen aussetzen.",
		"es": "Permitir 0.0.0.0/0 en una ACL omite los beneficios de seguridad del control de acceso, potencialmente exponiendo servicios a ataques.",
		"fr": "Autoriser 0.0.0.0/0 dans une ACL contourne les avantages de sécurité du contrôle d'accès, exposant potentiellement les services aux attaques.",
		"pt": "Permitir 0.0.0.0/0 em uma ACL ignora os benefícios de segurança do controle de acesso, potencialmente expondo serviços a ataques."
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from the SLB ACL entries and replace it with specific IP ranges.",
		"zh": "从 CLB 访问控制列表条目中移除 0.0.0.0/0，并替换为特定的 IP 范围。",
		"ja": "SLB ACL エントリから 0.0.0.0/0 を削除し、特定の IP 範囲に置き換えます。",
		"de": "Entfernen Sie 0.0.0.0/0 aus den SLB ACL-Einträgen und ersetzen Sie es durch spezifische IP-Bereiche.",
		"es": "Elimine 0.0.0.0/0 de las entradas de ACL de SLB y reemplácelo con rangos de IP específicos.",
		"fr": "Supprimez 0.0.0.0/0 des entrées ACL SLB et remplacez-le par des plages d'IP spécifiques.",
		"pt": "Remova 0.0.0.0/0 das entradas de ACL SLB e substitua por intervalos de IP específicos."
	},
	"resource_types": ["ALIYUN::SLB::AccessControl"]
}

is_compliant(resource) if {
	entries := helpers.get_property(resource, "AclEntries", [])
	not has_open_entry(entries)
}

has_open_entry(entries) if {
	some entry in entries
	helpers.is_public_cidr(entry.Entry)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::AccessControl")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AclEntries"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
