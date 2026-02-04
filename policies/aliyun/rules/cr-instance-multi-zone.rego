package infraguard.rules.aliyun.cr_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "cr-instance-multi-zone",
	"name": {
		"en": "CR Instance with Zone-Redundant OSS Bucket",
		"zh": "关联同城冗余的 oss 桶的容器镜像实例",
		"ja": "ゾーン冗長 OSS バケットを持つ CR インスタンス",
		"de": "CR-Instanz mit zonenredundantem OSS-Bucket",
		"es": "Instancia CR con Bucket OSS Redundante de Zona",
		"fr": "Instance CR avec Bucket OSS Redondant par Zone",
		"pt": "Instância CR com Bucket OSS Redundante de Zona",
	},
	"severity": "medium",
	"description": {
		"en": "Container Registry instances should be associated with zone-redundant OSS buckets for high availability.",
		"zh": "关联同城冗余的 oss 桶的容器镜像实例，视为合规。",
		"ja": "コンテナレジストリインスタンスは、高可用性のためにゾーン冗長 OSS バケットに関連付けられる必要があります。",
		"de": "Container Registry-Instanzen sollten mit zonenredundanten OSS-Buckets für Hochverfügbarkeit verknüpft werden.",
		"es": "Las instancias de Container Registry deben estar asociadas con buckets OSS redundantes de zona para alta disponibilidad.",
		"fr": "Les instances Container Registry doivent être associées à des buckets OSS redondants par zone pour une haute disponibilité.",
		"pt": "As instâncias do Container Registry devem estar associadas a buckets OSS redundantes de zona para alta disponibilidade.",
	},
	"reason": {
		"en": "The Container Registry instance is associated with a non-redundant OSS bucket, which may affect availability.",
		"zh": "容器镜像实例关联的 OSS 桶不是同城冗余类型，可能影响可用性。",
		"ja": "コンテナレジストリインスタンスが非冗長 OSS バケットに関連付けられているため、可用性に影響を与える可能性があります。",
		"de": "Die Container Registry-Instanz ist mit einem nicht redundanten OSS-Bucket verknüpft, was die Verfügbarkeit beeinträchtigen kann.",
		"es": "La instancia de Container Registry está asociada con un bucket OSS no redundante, lo que puede afectar la disponibilidad.",
		"fr": "L'instance Container Registry est associée à un bucket OSS non redondant, ce qui peut affecter la disponibilité.",
		"pt": "A instância do Container Registry está associada a um bucket OSS não redundante, o que pode afetar a disponibilidade.",
	},
	"recommendation": {
		"en": "Associate the Container Registry instance with an OSS bucket that has zone-redundant storage (ZRS) enabled.",
		"zh": "将容器镜像实例关联到启用了同城冗余存储（ZRS）的 OSS 桶。",
		"ja": "ゾーン冗長ストレージ（ZRS）が有効な OSS バケットにコンテナレジストリインスタンスを関連付けます。",
		"de": "Verknüpfen Sie die Container Registry-Instanz mit einem OSS-Bucket, der zonenredundanten Speicher (ZRS) aktiviert hat.",
		"es": "Asocie la instancia de Container Registry con un bucket OSS que tenga almacenamiento redundante de zona (ZRS) habilitado.",
		"fr": "Associez l'instance Container Registry à un bucket OSS qui a le stockage redondant par zone (ZRS) activé.",
		"pt": "Associe a instância do Container Registry a um bucket OSS que tenha armazenamento redundante de zona (ZRS) habilitado.",
	},
	"resource_types": ["ALIYUN::CR::Instance"],
}

# Get OSS bucket name from CR instance (handle both direct string and Ref)
get_oss_bucket_name(cr_instance) := bucket_name if {
	storage_name := cr_instance.Properties.InstanceStorageName
	is_string(storage_name)
	bucket_name := storage_name
}

get_oss_bucket_name(cr_instance) := bucket_name if {
	storage_name := cr_instance.Properties.InstanceStorageName
	is_object(storage_name)
	bucket_name := storage_name.Ref
}

# Check if associated OSS bucket is zone-redundant
has_zone_redundant_oss(cr_instance_name) if {
	bucket_name := get_oss_bucket_name(input.Resources[cr_instance_name])

	# Find the OSS bucket resource
	some oss_name, oss_resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	oss_name == bucket_name

	# Check if storage class is ZRS (Zone-Redundant Storage)
	storage_class := helpers.get_property(oss_resource, "StorageClass", "Standard")
	storage_class == "ZRS"
}

# Deny rule: CR instances must be associated with zone-redundant OSS buckets
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Instance")

	# Only check if custom OSS bucket is specified
	helpers.has_property(resource, "InstanceStorageName")

	# Check if not zone-redundant
	not has_zone_redundant_oss(name)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InstanceStorageName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
