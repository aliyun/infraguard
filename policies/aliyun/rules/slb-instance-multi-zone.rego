package infraguard.rules.aliyun.slb_instance_multi_zone

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "rule:aliyun:slb-instance-multi-zone",
	"name": {
		"en": "SLB Instance Multi-Zone Deployment",
		"zh": "SLB 实例多可用区部署",
	},
	"severity": "medium",
	"description": {
		"en": "SLB instances should be deployed across multiple zones by configuring both master and slave zones for high availability.",
		"zh": "SLB 实例应通过配置主可用区和备可用区来部署在多个可用区，以实现高可用性。",
	},
	"reason": {
		"en": "The SLB instance does not have a slave zone configured, which may affect availability during zone failures.",
		"zh": "SLB 实例未配置备可用区，在可用区故障时可能影响可用性。",
	},
	"recommendation": {
		"en": "Configure a slave zone by setting the SlaveZoneId property to enable multi-zone deployment.",
		"zh": "通过设置 SlaveZoneId 属性配置备可用区，以启用多可用区部署。",
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"],
}

# Check if instance has slave zone configured
has_slave_zone(resource) if {
	helpers.has_property(resource, "SlaveZoneId")
	slave_zone := resource.Properties.SlaveZoneId
	slave_zone != ""
}

# Deny rule: SLB instances should have slave zone configured
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not has_slave_zone(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SlaveZoneId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
