package infraguard.rules.aliyun.vpc_network_acl_risky_ports_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "vpc-network-acl-risky-ports-check",
	"name": {
		"en": "VPC Network ACL Risky Ports Check",
		"zh": "VPC 网络 ACL 禁用高风险端口"
	},
	"severity": "high",
	"description": {
		"en": "Ensures VPC Network ACLs do not allow unrestricted access to risky ports (22, 3389).",
		"zh": "确保 VPC 网络 ACL 不允许对风险端口（22, 3389）的无限制访问。"
	},
	"reason": {
		"en": "Opening management ports to all IPs (0.0.0.0/0) creates a significant security risk.",
		"zh": "向所有 IP（0.0.0.0/0）开放管理端口会造成重大的安全风险。"
	},
	"recommendation": {
		"en": "Restrict access to ports 22 and 3389 to specific trusted IP ranges.",
		"zh": "将对 22 和 3389 端口的访问限制在特定的可信 IP 范围内。"
	},
	"resource_types": ["ALIYUN::VPC::NetworkAcl"],
}

risky_ports := [22, 3389]

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NetworkAcl")
	entries := helpers.get_property(resource, "IngressAclEntries", [])
	some entry in entries
	entry.Policy == "accept"
	helpers.is_public_cidr(entry.SourceCidrIp)
	port_is_risky(entry.Port, risky_ports)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IngressAclEntries"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

port_is_risky(port, _) if {
	port == "all"
}

port_is_risky(port, target_ports) if {
	is_number(port)
	port in target_ports
}

port_is_risky(port, target_ports) if {
	is_string(port)
	parts := split(port, "/")
	count(parts) == 2
	start := to_number(parts[0])
	end := to_number(parts[1])
	some p in target_ports
	p >= start
	p <= end
}
