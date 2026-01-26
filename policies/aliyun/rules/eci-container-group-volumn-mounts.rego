package infraguard.rules.aliyun.eci_container_group_volumn_mounts

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "eci-container-group-volumn-mounts",
	"name": {
		"en": "ECI Volume Mounting Check",
		"zh": "ECI 容器组挂载卷核查"
	},
	"severity": "low",
	"description": {
		"en": "Ensures ECI container groups have volumes mounted for persistent data storage.",
		"zh": "确保 ECI 容器组挂载了用于持久化数据存储的卷。"
	},
	"reason": {
		"en": "Stateless containers may lose critical data upon restart if volumes are not mounted.",
		"zh": "如果未挂载卷，无状态容器在重启时可能会丢失关键数据。"
	},
	"recommendation": {
		"en": "Configure volumes and volume mounts for the ECI container group.",
		"zh": "为 ECI 容器组配置卷及卷挂载。"
	},
	"resource_types": ["ALIYUN::ECI::ContainerGroup"],
}

is_compliant(resource) if {
	volumes := helpers.get_property(resource, "Volume", [])
	count(volumes) > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECI::ContainerGroup")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Volume"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
