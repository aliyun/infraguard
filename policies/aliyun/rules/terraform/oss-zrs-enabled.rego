package infraguard.rules.terraform.oss_zrs_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-zrs-enabled",
	"severity": "medium",
	"name": {
		"en": "OSS Bucket Zone-Redundant Storage Enabled",
		"zh": "OSS 桶启用同城冗余存储",
		"ja": "OSS バケットのゾーン冗長ストレージが有効",
		"de": "OSS-Bucket zonenredundanter Speicher aktiviert",
		"es": "Almacenamiento con Redundancia de Zona de Bucket OSS Habilitado",
		"fr": "Stockage Redondant par Zone de Bucket OSS Activé",
		"pt": "Armazenamento com Redundância de Zona de Bucket OSS Habilitado"
	},
	"description": {
		"en": "Ensures OSS bucket uses Zone-Redundant Storage (ZRS) for high availability.",
		"zh": "确保 OSS 存储桶使用同城冗余存储 (ZRS) 以实现高可用性。",
		"ja": "OSS バケットは、高可用性とデータの耐久性のためにゾーン冗長ストレージ（ZRS）を使用する必要があります。",
		"de": "OSS-Buckets sollten zonenredundanten Speicher (ZRS) für hohe Verfügbarkeit und Datenbeständigkeit verwenden.",
		"es": "Los buckets OSS deben usar almacenamiento con redundancia de zona (ZRS) para alta disponibilidad y durabilidad de datos.",
		"fr": "Les buckets OSS doivent utiliser le stockage redondant par zone (ZRS) pour une haute disponibilité et une durabilité des données.",
		"pt": "Buckets OSS devem usar armazenamento com redundância de zona (ZRS) para alta disponibilidade e durabilidade de dados."
	},
	"reason": {
		"en": "The OSS bucket does not use Zone-Redundant Storage.",
		"zh": "OSS 存储桶未使用同城冗余存储。",
		"ja": "OSS バケットでゾーン冗長ストレージが有効になっていないため、データの可用性に影響を与える可能性があります。",
		"de": "Der OSS-Bucket hat keinen zonenredundanten Speicher aktiviert, was die Datenverfügbarkeit beeinträchtigen kann.",
		"es": "El bucket OSS no tiene almacenamiento con redundancia de zona habilitado, lo que puede afectar la disponibilidad de datos.",
		"fr": "Le bucket OSS n'a pas le stockage redondant par zone activé, ce qui peut affecter la disponibilité des données.",
		"pt": "O bucket OSS não tem armazenamento com redundância de zona habilitado, o que pode afetar a disponibilidade de dados."
	},
	"recommendation": {
		"en": "Set redundancy_type to 'ZRS' for zone-redundant storage.",
		"zh": "将 redundancy_type 设置为 'ZRS' 以使用同城冗余存储。",
		"ja": "バケット作成時に RedundancyType を 'ZRS' に設定して、ゾーン冗長ストレージを有効にします。",
		"de": "Aktivieren Sie zonenredundanten Speicher, indem Sie RedundancyType beim Erstellen des Buckets auf 'ZRS' setzen.",
		"es": "Habilite almacenamiento con redundancia de zona estableciendo RedundancyType en 'ZRS' al crear el bucket.",
		"fr": "Activez le stockage redondant par zone en définissant RedundancyType sur 'ZRS' lors de la création du bucket.",
		"pt": "Habilite armazenamento com redundância de zona definindo RedundancyType como 'ZRS' ao criar o bucket."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	redundancy_type := tf.get_attribute(resource, "redundancy_type", "LRS")
	not tf.is_unknown(redundancy_type)
	redundancy_type != "ZRS"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
