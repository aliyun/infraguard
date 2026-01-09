package infraguard.packs.aliyun.slb_application_best_practice

import rego.v1

pack_meta := {
	"id": "slb-application-best-practice",
	"name": {
		"en": "SLB Application Best Practice",
		"zh": "负载均衡应用最佳实践",
	},
	"description": {
		"en": "Best practices for SLB and ALB configuration, covering high availability, security, health checks, and operational settings.",
		"zh": "SLB 和 ALB 配置最佳实践,涵盖高可用、安全、健康检查和运维设置。",
	},
	"rules": [
		# "alb-instance-idle-check",
		"alb-all-listener-health-check-enabled",
		# "alb-acl-has-specified-ip",
		# "alb-all-listener-enabled-acl",  # Commented: ROS ALB::Listener does not support AclConfig property
		"alb-address-type-check",
		"slb-acl-public-access-check",
		"slb-listener-https-enabled",
		"slb-all-listener-servers-multi-zone",
		# "slb-instance-idle-check",
		"slb-all-listenter-tls-policy-check",
		"slb-all-listener-health-check-enabled",
		# "slb-acl-has-specified-ip",
		# "slb-instance-autorenewal-check",
		# "slb-instance-expired-check",
		"slb-instance-loadbalancerspec-check",
		"slb-instance-multi-zone",
		"slb-delete-protection-enabled",
		"slb-modify-protection-check",
		# "slb-instance-listener-count-check",
		# "slb-listener-health-check-interval-check",
		# "slb-listener-health-check-timeout-check",
		# "slb-listener-health-check-threshold-check",
		# "slb-listener-connection-drain-enabled",
		# "slb-listener-http2-enabled",
		# "slb-listener-gzip-enabled",
	],
}
