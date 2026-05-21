package infraguard.rules.aliyun.vpc_network_acl_not_empty

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "vpc-network-acl-not-empty",
	"severity": "medium",
	"name": {
		"en": "VPC Network ACL Not Empty",
		"zh": "专有网络 ACL 不为空条目",
		"ja": "VPC ネットワーク ACL が空でない",
		"de": "VPC-Netzwerk-ACL nicht leer",
		"es": "ACL de Red VPC No Vacío",
		"fr": "ACL de Réseau VPC Non Vide",
		"pt": "ACL de Rede VPC Não Vazio"
	},
	"description": {
		"en": "Ensures VPC Network ACLs have at least one rule configured.",
		"zh": "确保 VPC 网络 ACL 至少配置了一条规则。",
		"ja": "VPC ネットワーク ACL に少なくとも 1 つのルールが設定されていることを確認します。",
		"de": "Stellt sicher, dass VPC-Netzwerk-ACLs mindestens eine Regel konfiguriert haben.",
		"es": "Garantiza que las ACL de red VPC tengan al menos una regla configurada.",
		"fr": "Garantit que les ACL de réseau VPC ont au moins une règle configurée.",
		"pt": "Garante que as ACLs de rede VPC tenham pelo menos uma regra configurada."
	},
	"reason": {
		"en": "An empty ACL provides no security filtering, which might lead to unintended access.",
		"zh": "空的 ACL 不提供任何安全过滤，可能导致非预期的访问。",
		"ja": "空の ACL はセキュリティフィルタリングを提供しないため、意図しないアクセスにつながる可能性があります。",
		"de": "Eine leere ACL bietet keine Sicherheitsfilterung, was zu unbeabsichtigtem Zugriff führen kann.",
		"es": "Una ACL vacía no proporciona filtrado de seguridad, lo que podría provocar acceso no deseado.",
		"fr": "Une ACL vide ne fournit aucun filtrage de sécurité, ce qui peut entraîner un accès non intentionnel.",
		"pt": "Uma ACL vazia não fornece filtragem de segurança, o que pode levar a acesso não intencional."
	},
	"recommendation": {
		"en": "Add ingress and egress rules to the VPC Network ACL.",
		"zh": "为 VPC 网络 ACL 添加进方向和出方向规则。",
		"ja": "VPC ネットワーク ACL にイングレスとエグレスルールを追加します。",
		"de": "Fügen Sie Ein- und Ausgangsregeln zur VPC-Netzwerk-ACL hinzu.",
		"es": "Agregue reglas de entrada y salida a la ACL de red VPC.",
		"fr": "Ajoutez des règles d'entrée et de sortie à l'ACL de réseau VPC.",
		"pt": "Adicione regras de entrada e saída à ACL de rede VPC."
	},
	"resource_types": ["ALIYUN::VPC::NetworkAcl"]
}

is_compliant(resource) if {
	entries := helpers.get_property(resource, "IngressAclEntries", [])
	count(entries) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NetworkAcl")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IngressAclEntries"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
