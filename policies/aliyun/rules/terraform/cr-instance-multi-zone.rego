package infraguard.rules.terraform.cr_instance_multi_zone

import data.infraguard.helpers.terraform as tf
import rego.v1

rule_meta := {
	"id": "cr-instance-multi-zone",
	"severity": "medium",
	"name": {
		"en": "CR Instance with Zone-Redundant OSS Bucket",
		"zh": "关联同城冗余的 oss 桶的容器镜像实例",
		"ja": "ゾーン冗長 OSS バケットを持つ CR インスタンス",
		"de": "CR-Instanz mit zonenredundantem OSS-Bucket",
		"es": "Instancia CR con Bucket OSS Redundante de Zona",
		"fr": "Instance CR avec Bucket OSS Redondant par Zone",
		"pt": "Instância CR com Bucket OSS Redundante de Zona"
	},
	"description": {
		"en": "Container Registry instances should be associated with zone-redundant OSS buckets for high availability.",
		"zh": "关联同城冗余的 oss 桶的容器镜像实例，视为合规。",
		"ja": "コンテナレジストリインスタンスは、高可用性のためにゾーン冗長 OSS バケットに関連付けられる必要があります。",
		"de": "Container Registry-Instanzen sollten mit zonenredundanten OSS-Buckets für Hochverfügbarkeit verknüpft werden.",
		"es": "Las instancias de Container Registry deben estar asociadas con buckets OSS redundantes de zona para alta disponibilidad.",
		"fr": "Les instances Container Registry doivent être associées à des buckets OSS redondants par zone pour une haute disponibilité.",
		"pt": "As instâncias do Container Registry devem estar associadas a buckets OSS redundantes de zona para alta disponibilidade."
	},
	"reason": {
		"en": "The Container Registry instance is associated with a non-redundant OSS bucket, which may affect availability.",
		"zh": "容器镜像实例关联的 OSS 桶不是同城冗余类型，可能影响可用性。",
		"ja": "コンテナレジストリインスタンスが非冗長 OSS バケットに関連付けられているため、可用性に影響を与える可能性があります。",
		"de": "Die Container Registry-Instanz ist mit einem nicht redundanten OSS-Bucket verknüpft, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La instancia de Container Registry está asociada con un bucket OSS no redundante, lo que puede afectar la disponibilidad.",
		"fr": "L'instance Container Registry est associée à un bucket OSS non redondant, ce qui peut affecter la disponibilité.",
		"pt": "A instância do Container Registry está associada a um bucket OSS não redundante, o que pode afetar a disponibilidade."
	},
	"recommendation": {
		"en": "Associate the Container Registry instance with an OSS bucket that has zone-redundant storage (ZRS) enabled.",
		"zh": "将容器镜像实例关联到启用了同城冗余存储（ZRS）的 OSS 桶。",
		"ja": "ゾーン冗長ストレージ（ZRS）が有効な OSS バケットにコンテナレジストリインスタンスを関連付けます。",
		"de": "Verknüpfen Sie die Container Registry-Instanz mit einem OSS-Bucket, der zonenredundanten Speicher (ZRS) aktiviert hat.",
		"es": "Asocie la instancia de Container Registry con un bucket OSS que tenga almacenamiento redundante de zona (ZRS) habilitado.",
		"fr": "Associez l'instance Container Registry à un bucket OSS qui a le stockage redondant par zone (ZRS) activé.",
		"pt": "Associe a instância do Container Registry a um bucket OSS que tenha armazenamento redundante de zona (ZRS) habilitado."
	},
	"resource_types": ["alicloud_cr_ee_instance", "alicloud_oss_bucket"],
	"iac_type": "terraform"
}

associated_bucket_is_zrs(bucket_name) if {
	some _, bucket in tf.resources_by_type("alicloud_oss_bucket")
	tf.get_attribute(bucket, "bucket", "") == bucket_name
	tf.get_attribute(bucket, "redundancy_type", "LRS") == "ZRS"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cr_ee_instance")
	bucket_name := tf.get_attribute(resource, "custom_oss_bucket", "")
	bucket_name != ""
	not tf.is_unknown(bucket_name)
	not associated_bucket_is_zrs(bucket_name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_cr_ee_instance.%s", [name]),
		"violation_path": ["custom_oss_bucket"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
