# Resource Idle Detection Best Practice Pack
# Detect common cloud resources that are idle after purchase, involving EIP, shared bandwidth, VPC, VPN, etc.
# Idle resources lead to cost waste and should be identified and managed in time.
package infraguard.packs.aliyun.resource_idle_detection_best_practice

import rego.v1

# Pack metadata with i18n support
pack_meta := {
	"id": "resource-idle-detection-best-practice",
	"name": {
		"en": "Resource Idle Detection Best Practice",
		"zh": "资源空闲检测最佳实践",
	},
	"description": {
		"en": "Detect common cloud resources that are idle after purchase, involving EIP, shared bandwidth, VPC, VPN and other cloud products. Idle resources lead to enterprise cost waste and should be identified and managed in time.",
		"zh": "检测常见的云资源在购买以后是否被闲置，涉及弹性公网 IP、共享带宽、VPC、VPN 等云产品。资源购买后未启用会导致企业成本的浪费，建议及时发现并治理。",
	},
	"rules": ["ecs-disk-idle-check"], # "cr-instance-idle-check", # "alb-instance-idle-check", # "cbwp-bandwidth-package-idle-check",
	# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
	# "eip-idle-check",
	# "nas-filesystem-idle-check",
	# "internet-natgateway-idle-check",
	# "intranet-natgateway-idle-check",
	# "slb-instance-idle-check",
	# "vpn-gateway-idle-check"

}
