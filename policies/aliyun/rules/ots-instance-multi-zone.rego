package infraguard.rules.aliyun.ots_instance_multi_zone

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ots-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "OTS Instance Zone-Redundant Storage",
		"zh": "使用同城冗余的 OTS 实例",
		"ja": "OTS インスタンスゾーン冗長ストレージ",
		"de": "OTS-Instanz Zonenredundanter Speicher",
		"es": "Almacenamiento Redundante de Zona de Instancia OTS",
		"fr": "Stockage Redondant par Zone d'Instance OTS",
		"pt": "Armazenamento Redundante de Zona de Instância OTS"
	},
	"description": {
		"en": "Ensures Tablestore (OTS) instances use zone-redundant storage for high availability.",
		"zh": "确保 Tablestore（OTS）实例使用同城冗余存储以实现高可用性。",
		"ja": "Tablestore（OTS）インスタンスが高可用性のためにゾーン冗長ストレージを使用することを確認します。",
		"de": "Stellt sicher, dass Tablestore (OTS)-Instanzen zonenredundanten Speicher für Hochverfügbarkeit verwenden.",
		"es": "Garantiza que las instancias Tablestore (OTS) usen almacenamiento redundante de zona para alta disponibilidad.",
		"fr": "Garantit que les instances Tablestore (OTS) utilisent un stockage redondant par zone pour une haute disponibilité.",
		"pt": "Garante que as instâncias Tablestore (OTS) usem armazenamento redundante de zona para alta disponibilidade."
	},
	"reason": {
		"en": "Zone-redundant storage provides higher availability and protects against zone-level failures.",
		"zh": "同城冗余存储提供更高的可用性，并防止可用区级别的故障。",
		"ja": "ゾーン冗長ストレージは、より高い可用性を提供し、ゾーンレベルの障害から保護します。",
		"de": "Zonenredundanter Speicher bietet höhere Verfügbarkeit und schützt vor Zonenebenenausfällen.",
		"es": "El almacenamiento redundante de zona proporciona mayor disponibilidad y protege contra fallas a nivel de zona.",
		"fr": "Le stockage redondant par zone offre une disponibilité plus élevée et protège contre les défaillances au niveau de la zone.",
		"pt": "O armazenamento redundante de zona fornece maior disponibilidade e protege contra falhas no nível de zona."
	},
	"recommendation": {
		"en": "Use zone-redundant Tablestore instances for critical workloads.",
		"zh": "为关键工作负载使用同城冗余的 Tablestore 实例。",
		"ja": "重要なワークロードにはゾーン冗長 Tablestore インスタンスを使用します。",
		"de": "Verwenden Sie zonenredundante Tablestore-Instanzen für kritische Workloads.",
		"es": "Use instancias Tablestore redundantes de zona para cargas de trabajo críticas.",
		"fr": "Utilisez des instances Tablestore redondantes par zone pour les charges de travail critiques.",
		"pt": "Use instâncias Tablestore redundantes de zona para cargas de trabalho críticas."
	},
	"resource_types": ["ALIYUN::OTS::Instance"]
}

is_compliant(resource) if {
	# Check Network type for zone-redundant configuration
	# VPC_CONSIST or VPC with specific settings may indicate zone-redundant
	network := helpers.get_property(resource, "Network", "NORMAL")

	# NORMAL network type typically uses local redundancy
	# VPC_CONSIST indicates zone-redundant storage
	network == "VPC_CONSIST"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OTS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Network"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
