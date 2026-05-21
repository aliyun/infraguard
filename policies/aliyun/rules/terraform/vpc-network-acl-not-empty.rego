package infraguard.rules.terraform.vpc_network_acl_not_empty

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Add ingress_acl_entries blocks to the alicloud_network_acl resource.",
		"zh": "为 alicloud_network_acl 资源添加 ingress_acl_entries 配置块。",
		"ja": "alicloud_network_acl リソースに ingress_acl_entries ブロックを追加します。",
		"de": "Fügen Sie ingress_acl_entries-Blöcke zur alicloud_network_acl-Ressource hinzu.",
		"es": "Agregue bloques ingress_acl_entries al recurso alicloud_network_acl.",
		"fr": "Ajoutez des blocs ingress_acl_entries à la ressource alicloud_network_acl.",
		"pt": "Adicione blocos ingress_acl_entries ao recurso alicloud_network_acl."
	},
	"resource_types": ["alicloud_network_acl"],
	"iac_type": "terraform"
}

# Check if ACL has at least one ingress entry
has_ingress_entries(resource) if {
	entries := tf.get_attribute(resource, "ingress_acl_entries", [])
	not tf.is_unknown(entries)
	count(entries) > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_network_acl")
	not has_ingress_entries(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_network_acl.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
