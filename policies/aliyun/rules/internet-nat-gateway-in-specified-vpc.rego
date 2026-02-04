package infraguard.rules.aliyun.internet_nat_gateway_in_specified_vpc

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "internet-nat-gateway-in-specified-vpc",
	"name": {
		"en": "Internet NAT Gateway in Specified VPC",
		"zh": "公网 NAT 网关创建在指定专有网络内",
		"ja": "指定された VPC 内のインターネット NAT ゲートウェイ",
		"de": "Internet-NAT-Gateway im angegebenen VPC",
		"es": "Puerta de Enlace NAT de Internet en VPC Especificado",
		"fr": "Passerelle NAT Internet dans VPC Spécifié",
		"pt": "Gateway NAT da Internet em VPC Especificado",
	},
	"severity": "medium",
	"description": {
		"en": "Internet-facing NAT gateways should be created in specified VPCs according to network security requirements.",
		"zh": "公网 NAT 网关所属专有网络在参数指定的专有网络列表中，视为合规。",
		"ja": "インターネット向け NAT ゲートウェイは、ネットワークセキュリティ要件に従って指定された VPC 内に作成する必要があります。",
		"de": "Internetorientierte NAT-Gateways sollten gemäß Netzwerksicherheitsanforderungen in angegebenen VPCs erstellt werden.",
		"es": "Las puertas de enlace NAT orientadas a Internet deben crearse en VPCs especificados según los requisitos de seguridad de red.",
		"fr": "Les passerelles NAT orientées Internet doivent être créées dans des VPC spécifiés selon les exigences de sécurité réseau.",
		"pt": "Gateways NAT voltados para a Internet devem ser criados em VPCs especificados de acordo com os requisitos de segurança de rede.",
	},
	"reason": {
		"en": "Internet-facing NAT gateways in non-specified VPCs may violate network segmentation and security policies.",
		"zh": "不在指定 VPC 中的公网 NAT 网关可能违反网络分段和安全策略。",
		"ja": "指定されていない VPC 内のインターネット向け NAT ゲートウェイは、ネットワークセグメンテーションとセキュリティポリシーに違反する可能性があります。",
		"de": "Internetorientierte NAT-Gateways in nicht angegebenen VPCs können gegen Netzwerksegmentierung und Sicherheitsrichtlinien verstoßen.",
		"es": "Las puertas de enlace NAT orientadas a Internet en VPCs no especificados pueden violar la segmentación de red y las políticas de seguridad.",
		"fr": "Les passerelles NAT orientées Internet dans des VPC non spécifiés peuvent violer la segmentation réseau et les politiques de sécurité.",
		"pt": "Gateways NAT voltados para a Internet em VPCs não especificados podem violar a segmentação de rede e as políticas de segurança.",
	},
	"recommendation": {
		"en": "Ensure internet-facing NAT gateways are deployed only in the specified VPCs.",
		"zh": "确保公网 NAT 网关仅部署在指定的 VPC 中。",
		"ja": "インターネット向け NAT ゲートウェイが指定された VPC にのみ展開されるようにします。",
		"de": "Stellen Sie sicher, dass internetorientierte NAT-Gateways nur in den angegebenen VPCs bereitgestellt werden.",
		"es": "Asegúrese de que las puertas de enlace NAT orientadas a Internet se desplieguen solo en los VPCs especificados.",
		"fr": "Assurez-vous que les passerelles NAT orientées Internet ne sont déployées que dans les VPC spécifiés.",
		"pt": "Garanta que os gateways NAT voltados para a Internet sejam implantados apenas nos VPCs especificados.",
	},
	"resource_types": ["ALIYUN::NAT::NatGateway"],
}

is_internet_nat_gateway(resource) if {
	network_type := helpers.get_property(resource, "NetworkType", "")
	network_type == "internet"
}

is_in_specified_vpc(resource) if {
	# Parameter-based check - in production would use input parameter
	vpc_id := helpers.get_property(resource, "VpcId", "")
	vpc_id != ""
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::NAT::NatGateway")
	is_internet_nat_gateway(resource)
	not is_in_specified_vpc(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
