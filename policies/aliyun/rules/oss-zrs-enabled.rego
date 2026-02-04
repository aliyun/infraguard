package infraguard.rules.aliyun.oss_zrs_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "oss-zrs-enabled",
	"name": {
		"en": "OSS Bucket Zone-Redundant Storage Enabled",
		"zh": "OSS 桶启用同城冗余存储",
		"ja": "OSS バケットのゾーン冗長ストレージが有効",
		"de": "OSS-Bucket zonenredundanter Speicher aktiviert",
		"es": "Almacenamiento con Redundancia de Zona de Bucket OSS Habilitado",
		"fr": "Stockage Redondant par Zone de Bucket OSS Activé",
		"pt": "Armazenamento com Redundância de Zona de Bucket OSS Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "OSS buckets should use zone-redundant storage (ZRS) for high availability and data durability.",
		"zh": "OSS 桶应使用同城冗余存储（ZRS）以实现高可用性和数据持久性。",
		"ja": "OSS バケットは、高可用性とデータの耐久性のためにゾーン冗長ストレージ（ZRS）を使用する必要があります。",
		"de": "OSS-Buckets sollten zonenredundanten Speicher (ZRS) für hohe Verfügbarkeit und Datenbeständigkeit verwenden.",
		"es": "Los buckets OSS deben usar almacenamiento con redundancia de zona (ZRS) para alta disponibilidad y durabilidad de datos.",
		"fr": "Les buckets OSS doivent utiliser le stockage redondant par zone (ZRS) pour une haute disponibilité et une durabilité des données.",
		"pt": "Buckets OSS devem usar armazenamento com redundância de zona (ZRS) para alta disponibilidade e durabilidade de dados.",
	},
	"reason": {
		"en": "The OSS bucket does not have zone-redundant storage enabled, which may affect data availability.",
		"zh": "OSS 桶未启用同城冗余存储，可能影响数据可用性。",
		"ja": "OSS バケットでゾーン冗長ストレージが有効になっていないため、データの可用性に影響を与える可能性があります。",
		"de": "Der OSS-Bucket hat keinen zonenredundanten Speicher aktiviert, was die Datenverfügbarkeit beeinträchtigen kann.",
		"es": "El bucket OSS no tiene almacenamiento con redundancia de zona habilitado, lo que puede afectar la disponibilidad de datos.",
		"fr": "Le bucket OSS n'a pas le stockage redondant par zone activé, ce qui peut affecter la disponibilité des données.",
		"pt": "O bucket OSS não tem armazenamento com redundância de zona habilitado, o que pode afetar a disponibilidade de dados.",
	},
	"recommendation": {
		"en": "Enable zone-redundant storage by setting RedundancyType to 'ZRS' when creating the bucket.",
		"zh": "在创建桶时通过将 RedundancyType 设置为'ZRS'来启用同城冗余存储。",
		"ja": "バケット作成時に RedundancyType を 'ZRS' に設定して、ゾーン冗長ストレージを有効にします。",
		"de": "Aktivieren Sie zonenredundanten Speicher, indem Sie RedundancyType beim Erstellen des Buckets auf 'ZRS' setzen.",
		"es": "Habilite almacenamiento con redundancia de zona estableciendo RedundancyType en 'ZRS' al crear el bucket.",
		"fr": "Activez le stockage redondant par zone en définissant RedundancyType sur 'ZRS' lors de la création du bucket.",
		"pt": "Habilite armazenamento com redundância de zona definindo RedundancyType como 'ZRS' ao criar o bucket.",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

# Check if bucket has ZRS enabled
has_zrs_enabled(resource) if {
	redundancy_type := helpers.get_property(resource, "RedundancyType", "LRS")
	redundancy_type == "ZRS"
}

# Deny rule: OSS buckets should have ZRS enabled
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not has_zrs_enabled(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RedundancyType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
