package infraguard.rules.aliyun.mse_gateway_multi_availability_area_architecture_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "mse-gateway-multi-availability-area-architecture-check",
	"name": {
		"en": "MSE Gateway Multi-Availability Zone Deployment",
		"zh": "MSE 云原生网关部署在多可用区",
	},
	"severity": "medium",
	"description": {
		"en": "MSE gateways should be deployed across multiple availability zones by configuring a backup VSwitch.",
		"zh": "MSE 云原生网关部署在多可用区，视为合规。",
	},
	"reason": {
		"en": "The MSE gateway does not have a backup VSwitch configured, which may affect availability.",
		"zh": "MSE 网关未配置备用交换机，可能影响可用性。",
	},
	"recommendation": {
		"en": "Configure a backup VSwitch by setting the BackupVSwitchId property to enable multi-zone deployment.",
		"zh": "通过设置 BackupVSwitchId 属性配置备用交换机，以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::MSE::Gateway"],
}

# Check if gateway has backup VSwitch
has_backup_vswitch(resource) if {
	helpers.has_property(resource, "BackupVSwitchId")
	backup_vswitch := resource.Properties.BackupVSwitchId
	backup_vswitch != ""
}

# Deny rule: MSE gateways should have backup VSwitch
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Gateway")
	not has_backup_vswitch(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "BackupVSwitchId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
