package infraguard.rules.aliyun.cr_repository_image_scanning_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "cr-repository-image-scanning-enabled",
	"name": {
		"en": "CR Instance Image Scanning Enabled",
		"zh": "为容器镜像实例开启安全扫描"
	},
	"severity": "high",
	"description": {
		"en": "Ensures Container Registry instances have image scanning enabled for security vulnerability detection.",
		"zh": "确保容器镜像实例开启了镜像安全扫描功能以检测安全漏洞。"
	},
	"reason": {
		"en": "Image scanning helps identify and prevent deployment of vulnerable container images.",
		"zh": "镜像扫描有助于识别和防止部署有漏洞的容器镜像。"
	},
	"recommendation": {
		"en": "Enable image scanning for the Container Registry instance.",
		"zh": "为容器镜像实例启用镜像扫描功能。"
	},
	"resource_types": ["ALIYUN::CR::Instance"],
}

is_compliant(resource) if {
	# Check ImageScanner property
	image_scanner := helpers.get_property(resource, "ImageScanner", "")
	count(image_scanner) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ImageScanner"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
