package infraguard.rules.aliyun.api_gateway_group_force_https

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rule:aliyun:api-gateway-group-force-https",
	"name": {
		"en": "API Gateway Group Force HTTPS",
		"zh": "API 分组绑定独立域名并开启 Https 强制跳转"
	},
	"severity": "high",
	"description": {
		"en": "Ensures API Gateway groups with public custom domains have HTTPS force redirect enabled.",
		"zh": "检测网关分组下的所有公网独立域名是否都开启 HTTPS 强制跳转。"
	},
	"reason": {
		"en": "HTTPS force redirect ensures all traffic is encrypted.",
		"zh": "HTTPS 强制跳转确保所有流量都经过加密。"
	},
	"recommendation": {
		"en": "Enable HTTPS force redirect for all public domains.",
		"zh": "为所有公网域名启用 HTTPS 强制跳转。"
	},
	"resource_types": ["ALIYUN::ApiGateway::Group"],
}

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	some domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")

	# Check if domain is bound to this group (direct match via Ref)
	helpers.is_referencing(bound_group_id, group_name)

	domain_name := helpers.get_property(domain_resource, "DomainName", "")
	is_public_domain(domain_name)

	cert_body := helpers.get_property(domain_resource, "CertificateBody", "")
	cert_key := helpers.get_property(domain_resource, "CertificatePrivateKey", "")
	cert_body == ""
	cert_key == ""

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "CustomDomains"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains result if {
	some group_name, group_resource in helpers.resources_by_type("ALIYUN::ApiGateway::Group")

	some domain_resource in helpers.resources_by_type("ALIYUN::ApiGateway::CustomDomain")
	bound_group_id := helpers.get_property(domain_resource, "GroupId", "")

	# Check if domain is bound to this group (Fn::GetAtt reference)
	helpers.is_get_att_referencing(bound_group_id, group_name)

	domain_name := helpers.get_property(domain_resource, "DomainName", "")
	is_public_domain(domain_name)

	cert_body := helpers.get_property(domain_resource, "CertificateBody", "")
	cert_key := helpers.get_property(domain_resource, "CertificatePrivateKey", "")
	cert_body == ""
	cert_key == ""

	result := {
		"id": rule_meta.id,
		"resource_id": group_name,
		"violation_path": ["Properties", "CustomDomains"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

is_public_domain(domain) if {
	not contains(domain, ".internal.")
	not contains(domain, ".local")
}
