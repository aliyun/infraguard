package infraguard.rules.terraform.sls_project_multi_zone

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "sls-project-multi-zone",
	"severity": "medium",
	"name": {
		"en": "SLS Project Zone-Redundant Storage",
		"zh": "SLS 项目使用同城冗余存储",
		"ja": "SLS プロジェクトゾーン冗長ストレージ",
		"de": "SLS-Projekt Zonenredundanter Speicher",
		"es": "Almacenamiento Redundante de Zona del Proyecto SLS",
		"fr": "Stockage Redondant par Zone du Projet SLS",
		"pt": "Armazenamento Redundante de Zona do Projeto SLS"
	},
	"description": {
		"en": "SLS projects should use zone-redundant storage (ZRS) for high availability and data durability.",
		"zh": "SLS 项目应使用同城冗余存储（ZRS）以实现高可用性和数据持久性。",
		"ja": "SLS プロジェクトは、高可用性とデータの耐久性のためにゾーン冗長ストレージ（ZRS）を使用する必要があります。",
		"de": "SLS-Projekte sollten zonenredundanten Speicher (ZRS) für Hochverfügbarkeit und Datenbeständigkeit verwenden.",
		"es": "Los proyectos SLS deben usar almacenamiento redundante de zona (ZRS) para alta disponibilidad y durabilidad de datos.",
		"fr": "Les projets SLS doivent utiliser un stockage redondant par zone (ZRS) pour une haute disponibilité et une durabilité des données.",
		"pt": "Os projetos SLS devem usar armazenamento redundante de zona (ZRS) para alta disponibilidade e durabilidade dos dados."
	},
	"reason": {
		"en": "The SLS project does not use zone-redundant storage, which may affect data availability.",
		"zh": "SLS 项目未使用同城冗余存储，可能影响数据可用性。",
		"ja": "SLS プロジェクトがゾーン冗長ストレージを使用していないため、データの可用性に影響を与える可能性があります。",
		"de": "Das SLS-Projekt verwendet keinen zonenredundanten Speicher, was die Datenverfügbarkeit beeinträchtigen kann.",
		"es": "El proyecto SLS no usa almacenamiento redundante de zona, lo que puede afectar la disponibilidad de datos.",
		"fr": "Le projet SLS n'utilise pas de stockage redondant par zone, ce qui peut affecter la disponibilité des données.",
		"pt": "O projeto SLS não usa armazenamento redundante de zona, o que pode afetar a disponibilidade dos dados."
	},
	"recommendation": {
		"en": "Set data_redundancy_type to 'ZRS' when creating the SLS project for zone-redundant storage.",
		"zh": "创建 SLS 项目时将 data_redundancy_type 设置为 'ZRS' 以使用同城冗余存储。",
		"ja": "ゾーン冗長ストレージのために SLS プロジェクト作成時に data_redundancy_type を 'ZRS' に設定します。",
		"de": "Setzen Sie data_redundancy_type auf 'ZRS' beim Erstellen des SLS-Projekts für zonenredundanten Speicher.",
		"es": "Establezca data_redundancy_type en 'ZRS' al crear el proyecto SLS para almacenamiento redundante de zona.",
		"fr": "Définissez data_redundancy_type sur 'ZRS' lors de la création du projet SLS pour un stockage redondant par zone.",
		"pt": "Defina data_redundancy_type como 'ZRS' ao criar o projeto SLS para armazenamento redundante de zona."
	},
	"resource_types": ["alicloud_log_project"],
	"iac_type": "terraform"
}

is_zone_redundant(resource) if {
	redundancy_type := tf.get_attribute(resource, "data_redundancy_type", "")
	redundancy_type == "ZRS"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_log_project")
	not is_zone_redundant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_log_project.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
