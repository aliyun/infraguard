package infraguard.rules.aliyun.cr_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:cr-instance-multi-zone",
	"name": {
		"en": "CR Instance with Zone-Redundant OSS Bucket",
		"zh": "关联同城冗余的 oss 桶的容器镜像实例",
	},
	"severity": "medium",
	"description": {
		"en": "Container Registry instances should be associated with zone-redundant OSS buckets for high availability.",
		"zh": "关联同城冗余的 oss 桶的容器镜像实例，视为合规。",
	},
	"reason": {
		"en": "The Container Registry instance is associated with a non-redundant OSS bucket, which may affect availability.",
		"zh": "容器镜像实例关联的 OSS 桶不是同城冗余类型，可能影响可用性。",
	},
	"recommendation": {
		"en": "Associate the Container Registry instance with an OSS bucket that has zone-redundant storage (ZRS) enabled.",
		"zh": "将容器镜像实例关联到启用了同城冗余存储（ZRS）的 OSS 桶。",
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
