package infraguard.rules.terraform.eip_attached

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "eip-attached",
	"severity": "low",
	"name": {
		"en": "EIP Attached",
		"zh": "EIP 必须处于绑定状态",
		"ja": "EIP がアタッチされている",
		"de": "EIP angehängt",
		"es": "EIP Adjunto",
		"fr": "EIP Attaché",
		"pt": "EIP Anexado"
	},
	"description": {
		"en": "Ensures that EIP instances are associated with a resource.",
		"zh": "确保 EIP 实例已与资源关联。",
		"ja": "EIP インスタンスがリソースに関連付けられていることを確認します。",
		"de": "Stellt sicher, dass EIP-Instanzen einer Ressource zugeordnet sind.",
		"es": "Garantiza que las instancias EIP estén asociadas con un recurso.",
		"fr": "Garantit que les instances EIP sont associées à une ressource.",
		"pt": "Garante que as instâncias EIP estejam associadas a um recurso."
	},
	"reason": {
		"en": "Unattached EIPs incur costs without providing any service.",
		"zh": "未绑定的 EIP 会产生费用，但未提供任何服务。",
		"ja": "アタッチされていない EIP は、サービスを提供せずにコストが発生します。",
		"de": "Nicht angehängte EIPs verursachen Kosten, ohne einen Dienst bereitzustellen.",
		"es": "Los EIP no adjuntos incurren en costos sin proporcionar ningún servicio.",
		"fr": "Les EIP non attachés entraînent des coûts sans fournir de service.",
		"pt": "EIPs não anexados incorrem em custos sem fornecer nenhum serviço."
	},
	"recommendation": {
		"en": "Associate the EIP with an ECS instance, NAT Gateway, or Load Balancer.",
		"zh": "将 EIP 与 ECS 实例、NAT 网关或负载均衡器关联。",
		"ja": "EIP を ECS インスタンス、NAT ゲートウェイ、またはロードバランサーに関連付けます。",
		"de": "Ordnen Sie die EIP einer ECS-Instanz, einem NAT-Gateway oder einem Load Balancer zu.",
		"es": "Asocie el EIP con una instancia ECS, puerta de enlace NAT o equilibrador de carga.",
		"fr": "Associez l'EIP à une instance ECS, une passerelle NAT ou un équilibreur de charge.",
		"pt": "Associe o EIP a uma instância ECS, Gateway NAT ou Load Balancer."
	},
	"resource_types": ["alicloud_eip_address", "alicloud_eip_association"],
	"iac_type": "terraform"
}

identifier_matches(resource, name, allocation_id) if {
	allocation_id == name
}

identifier_matches(resource, name, allocation_id) if {
	id := tf.get_attribute(resource, "id", "")
	not tf.is_unknown(id)
	id != ""
	allocation_id != ""
	allocation_id == id
}

identifier_matches(resource, name, allocation_id) if {
	eip_allocation_id := tf.get_attribute(resource, "allocation_id", "")
	not tf.is_unknown(eip_allocation_id)
	eip_allocation_id != ""
	allocation_id != ""
	allocation_id == eip_allocation_id
}

is_attached(resource, name) if {
	some _, association in tf.resources_by_type("alicloud_eip_association")
	allocation_id := tf.get_attribute(association, "allocation_id", "")
	not tf.is_unknown(allocation_id)
	identifier_matches(resource, name, allocation_id)
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_eip_address.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_eip_address")
	not is_attached(resource, name)
	violation := violation_for(name)
}
