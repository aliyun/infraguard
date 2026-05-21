package infraguard.rules.terraform.ots_instance_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ots-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "OTS Instance Zone-Redundant Storage",
		"zh": "使用同城冗余的 OTS 实例",
		"ja": "OTS インスタンスゾーン冗長ストレージ",
		"de": "OTS-Instanz zonenredundanter Speicher",
		"es": "Almacenamiento Redundante por Zona de Instancia OTS",
		"fr": "Stockage Redondant par Zone d'Instance OTS",
		"pt": "Armazenamento Redundante por Zona de Instância OTS"
	},
	"description": {
		"en": "OTS instances should use zone-redundant access mode (ConsoleOrVpc) for high availability.",
		"zh": "OTS 实例应使用同城冗余访问模式（ConsoleOrVpc）以实现高可用性。",
		"ja": "OTS インスタンスは高可用性のためにゾーン冗長アクセスモード（ConsoleOrVpc）を使用する必要があります。",
		"de": "OTS-Instanzen sollten den zonenredundanten Zugriffsmodus (ConsoleOrVpc) für hohe Verfügbarkeit verwenden.",
		"es": "Las instancias OTS deben usar el modo de acceso redundante por zona (ConsoleOrVpc) para alta disponibilidad.",
		"fr": "Les instances OTS doivent utiliser le mode d'accès redondant par zone (ConsoleOrVpc) pour la haute disponibilité.",
		"pt": "As instâncias OTS devem usar o modo de acesso redundante por zona (ConsoleOrVpc) para alta disponibilidade."
	},
	"reason": {
		"en": "The OTS instance is not using zone-redundant access mode, which may affect availability during zone failures.",
		"zh": "OTS 实例未使用同城冗余访问模式，在可用区故障时可能影响可用性。",
		"ja": "OTS インスタンスはゾーン冗長アクセスモードを使用していないため、ゾーン障害時に可用性に影響する可能性があります。",
		"de": "Die OTS-Instanz verwendet keinen zonenredundanten Zugriffsmodus, was die Verfügbarkeit bei Zonenausfällen beeinträchtigen kann.",
		"es": "La instancia OTS no está usando el modo de acceso redundante por zona, lo que puede afectar la disponibilidad durante fallas de zona.",
		"fr": "L'instance OTS n'utilise pas le mode d'accès redondant par zone, ce qui peut affecter la disponibilité lors de pannes de zone.",
		"pt": "A instância OTS não está usando o modo de acesso redundante por zona, o que pode afetar a disponibilidade durante falhas de zona."
	},
	"recommendation": {
		"en": "Set accessed_by to 'ConsoleOrVpc' for zone-redundant access.",
		"zh": "将 accessed_by 设置为 'ConsoleOrVpc' 以实现同城冗余访问。",
		"ja": "ゾーン冗長アクセスのために accessed_by を 'ConsoleOrVpc' に設定します。",
		"de": "Setzen Sie accessed_by auf 'ConsoleOrVpc' für zonenredundanten Zugriff.",
		"es": "Establezca accessed_by en 'ConsoleOrVpc' para acceso redundante por zona.",
		"fr": "Définissez accessed_by sur 'ConsoleOrVpc' pour un accès redondant par zone.",
		"pt": "Defina accessed_by como 'ConsoleOrVpc' para acesso redundante por zona."
	},
	"resource_types": ["alicloud_ots_instance"],
	"iac_type": "terraform"
}

is_zone_redundant(resource) if {
	accessed_by := tf.get_attribute(resource, "accessed_by", "")
	not tf.is_unknown(accessed_by)
	accessed_by == "ConsoleOrVpc"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ots_instance")
	not is_zone_redundant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ots_instance.%s", [name]),
		"violation_path": ["accessed_by"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
