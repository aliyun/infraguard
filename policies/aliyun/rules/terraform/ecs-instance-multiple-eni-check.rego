package infraguard.rules.terraform.ecs_instance_multiple_eni_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-multiple-eni-check",
	"severity": "low",
	"name": {
		"en": "ECS instance is bound to only one elastic network interface",
		"zh": "ECS 实例仅绑定一个弹性网卡",
		"ja": "ECS インスタンスが1つのエラスティックネットワークインターフェースにのみバインドされている",
		"de": "ECS-Instanz ist nur an eine elastische Netzwerkschnittstelle gebunden",
		"es": "La Instancia ECS Está Vinculada Solo a Una Interfaz de Red Elástica",
		"fr": "L'Instance ECS est Liée à Une Seule Interface Réseau Élastique",
		"pt": "A Instância ECS Está Vinculada Apenas a Uma Interface de Rede Elástica"
	},
	"description": {
		"en": "ECS instances are bound to only one elastic network interface, considered compliant. This helps simplify network configuration and reduce complexity.",
		"zh": "ECS 实例仅绑定一个弹性网卡，视为合规。这有助于简化网络配置并减少复杂性。",
		"ja": "ECS インスタンスが1つのエラスティックネットワークインターフェースにのみバインドされており、準拠と見なされます。これにより、ネットワーク設定が簡素化され、複雑さが軽減されます。",
		"de": "ECS-Instanzen sind nur an eine elastische Netzwerkschnittstelle gebunden, was als konform gilt. Dies hilft, die Netzwerkkonfiguration zu vereinfachen und die Komplexität zu reduzieren.",
		"es": "Las instancias ECS están vinculadas solo a una interfaz de red elástica, considerado conforme. Esto ayuda a simplificar la configuración de red y reducir la complejidad.",
		"fr": "Les instances ECS sont liées à une seule interface réseau élastique, considéré comme conforme. Cela aide à simplifier la configuration réseau et à réduire la complexité.",
		"pt": "As instâncias ECS estão vinculadas apenas a uma interface de rede elástica, considerado conforme. Isso ajuda a simplificar a configuração de rede e reduzir a complexidade."
	},
	"reason": {
		"en": "ECS instance is bound to multiple elastic network interfaces",
		"zh": "ECS 实例绑定了多个弹性网卡",
		"ja": "ECS インスタンスが複数のエラスティックネットワークインターフェースにバインドされている",
		"de": "ECS-Instanz ist an mehrere elastische Netzwerkschnittstellen gebunden",
		"es": "La instancia ECS está vinculada a múltiples interfaces de red elásticas",
		"fr": "L'instance ECS est liée à plusieurs interfaces réseau élastiques",
		"pt": "A instância ECS está vinculada a múltiplas interfaces de rede elásticas"
	},
	"recommendation": {
		"en": "Simplify instance network configuration by using only one ENI",
		"zh": "通过仅使用一个 ENI 来简化实例网络配置",
		"ja": "1つの ENI のみを使用してインスタンスネットワーク設定を簡素化します",
		"de": "Vereinfachen Sie die Instanznetzwerkkonfiguration, indem Sie nur eine ENI verwenden",
		"es": "Simplifique la configuración de red de la instancia usando solo una ENI",
		"fr": "Simplifiez la configuration réseau de l'instance en utilisant une seule ENI",
		"pt": "Simplifique a configuração de rede da instância usando apenas uma ENI"
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

violation_for(name) := {
	"id": rule_meta.id,
	"resource_id": sprintf("alicloud_instance.%s", [name]),
	"meta": {
		"severity": rule_meta.severity,
		"reason": rule_meta.reason,
		"recommendation": rule_meta.recommendation,
	},
}

has_multiple_inline_enis(resource) if {
	network_interfaces := tf.get_attribute(resource, "network_interfaces", [])
	not tf.is_unknown(network_interfaces)
	count(network_interfaces) > 1
}

has_multiple_inline_enis(resource) if {
	network_interface_ids := tf.get_attribute(resource, "network_interface_ids", [])
	not tf.is_unknown(network_interface_ids)
	count(network_interface_ids) > 1
}

attachment_targets_instance(attachment, name) if {
	instance_id := tf.get_attribute(attachment, "instance_id", "")
	not tf.is_unknown(instance_id)
	instance_id == name
}

attachment_targets_instance(attachment, name) if {
	instance_id := tf.get_attribute(attachment, "instance_id", "")
	not tf.is_unknown(instance_id)
	instance_id == sprintf("alicloud_instance.%s.id", [name])
}

has_multiple_attached_enis(name) if {
	attachment_count := count([att_name |
		some att_name, attachment in tf.resources_by_type("alicloud_network_interface_attachment")
		attachment_targets_instance(attachment, name)
	])
	attachment_count > 1
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	has_multiple_inline_enis(resource)
	violation := violation_for(name)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	has_multiple_attached_enis(name)
	violation := violation_for(name)
}
