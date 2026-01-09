package infraguard.rules.aliyun.sg_risky_ports_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rule:aliyun:sg-risky-ports-check",
	"name": {
		"en": "Security group does not open risky ports to 0.0.0.0/0",
		"zh": "安全组不允许对全部网段开启风险端口",
	},
	"description": {
		"en": "When security group ingress rule source is set to 0.0.0.0/0, the port range should not include specified risky ports, considered compliant. If source is not 0.0.0.0/0, it's compliant even if risky ports are included.",
		"zh": "当安全组入网网段设置为 0.0.0.0/0 时，端口范围不包含指定风险端口，视为合规。若入网网段未设置为 0.0.0.0/0 时，即使端口范围包含指定的风险端口，也视为合规。",
	},
	"severity": "high",
	"resource_types": ["ALIYUN::ECS::SecurityGroup"],
	"reason": {
		"en": "Security group opens risky ports to all IP addresses (0.0.0.0/0)",
		"zh": "安全组向所有 IP 地址(0.0.0.0/0)开放了风险端口",
	},
	"recommendation": {
		"en": "Remove risky port rules from security group ingress rules or restrict source IP range",
		"zh": "从安全组入站规则中删除风险端口规则，或限制源 IP 范围",
	},
}

# Risky port ranges to check (common sensitive ports)
# Format: port ranges like "22/22", "3389/3389", "0/65535"
is_risky_port(port_range) if {
	# Common risky ports: SSH (22), RDP (3389), Telnet (23), MySQL (3306), etc.
	port_range in [
		"22/22",
		"23/23",
		"3389/3389",
		"3306/3306",
		"1433/1433",
		"5432/5432",
		"27017/27017",
		"6379/6379",
		"0/65535",
	]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")

	# Get ingress rules
	ingress_rules := helpers.get_property(resource, "SecurityGroupIngress", [])

	# Check each rule
	some rule in ingress_rules
	source_cidr := object.get(rule, "SourceCidrIp", "")
	port_range := object.get(rule, "PortRange", "")

	# Only flag if source is 0.0.0.0/0 and port is risky
	source_cidr == "0.0.0.0/0"
	is_risky_port(port_range)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", "SourceCidrIp"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
