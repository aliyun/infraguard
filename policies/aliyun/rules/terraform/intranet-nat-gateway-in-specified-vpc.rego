package infraguard.rules.terraform.intranet_nat_gateway_in_specified_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "intranet-nat-gateway-in-specified-vpc",
	"severity": "medium",
	"name": {
		"en": "Intranet NAT Gateway in Specified VPC",
		"zh": "VPC NAT 网关创建在指定专有网络内",
		"ja": "指定された VPC 内のイントラネット NAT ゲートウェイ",
		"de": "Intranet-NAT-Gateway im angegebenen VPC",
		"es": "Puerta de Enlace NAT de Intranet en VPC Especificado",
		"fr": "Passerelle NAT Intranet dans VPC Spécifié",
		"pt": "Gateway NAT da Intranet em VPC Especificado"
	},
	"description": {
		"en": "Intranet NAT gateways should be created in specified VPCs according to network security requirements.",
		"zh": "VPC NAT 网关所属专有网络在参数指定的专有网络列表中，视为合规。",
		"ja": "イントラネット NAT ゲートウェイは、ネットワークセキュリティ要件に従って指定された VPC 内に作成する必要があります。",
		"de": "Intranet-NAT-Gateways sollten gemäß Netzwerksicherheitsanforderungen in angegebenen VPCs erstellt werden.",
		"es": "Las puertas de enlace NAT de intranet deben crearse en VPCs especificados según los requisitos de seguridad de red.",
		"fr": "Les passerelles NAT intranet doivent être créées dans des VPC spécifiés selon les exigences de sécurité réseau.",
		"pt": "Gateways NAT de intranet devem ser criados em VPCs especificados de acordo com os requisitos de segurança de rede."
	},
	"reason": {
		"en": "Intranet NAT gateways in non-specified VPCs may violate network segmentation and security policies.",
		"zh": "不在指定 VPC 中的 VPC NAT 网关可能违反网络分段和安全策略。",
		"ja": "指定されていない VPC 内のイントラネット NAT ゲートウェイは、ネットワークセグメンテーションとセキュリティポリシーに違反する可能性があります。",
		"de": "Intranet-NAT-Gateways in nicht angegebenen VPCs können gegen Netzwerksegmentierung und Sicherheitsrichtlinien verstoßen.",
		"es": "Las puertas de enlace NAT de intranet en VPCs no especificados pueden violar la segmentación de red y las políticas de seguridad.",
		"fr": "Les passerelles NAT intranet dans des VPC non spécifiés peuvent violer la segmentation réseau et les politiques de sécurité.",
		"pt": "Gateways NAT de intranet em VPCs não especificados podem violar a segmentação de rede e as políticas de segurança."
	},
	"recommendation": {
		"en": "Ensure intranet NAT gateways are deployed only in the specified VPCs.",
		"zh": "确保 VPC NAT 网关仅部署在指定的 VPC 中。",
		"ja": "イントラネット NAT ゲートウェイが指定された VPC にのみ展開されるようにします。",
		"de": "Stellen Sie sicher, dass Intranet-NAT-Gateways nur in den angegebenen VPCs bereitgestellt werden.",
		"es": "Asegúrese de que las puertas de enlace NAT de intranet se desplieguen solo en los VPCs especificados.",
		"fr": "Assurez-vous que les passerelles NAT intranet ne sont déployées que dans les VPC spécifiés.",
		"pt": "Garanta que os gateways NAT de intranet sejam implantados apenas nos VPCs especificados."
	},
	"resource_types": ["alicloud_nat_gateway"],
	"iac_type": "terraform"
}

is_intranet_nat_gateway(resource) if {
	network_type := tf.get_attribute(resource, "network_type", "")
	not tf.is_unknown(network_type)
	lower(network_type) == "intranet"
}

is_in_specified_vpc(resource) if {
	vpc_id := tf.get_attribute(resource, "vpc_id", "")
	not tf.is_unknown(vpc_id)
	vpc_id != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nat_gateway")
	is_intranet_nat_gateway(resource)
	not is_in_specified_vpc(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nat_gateway.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
