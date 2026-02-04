package infraguard.rules.aliyun.ecs_instance_multiple_eni_check

import rego.v1

import data.infraguard.helpers

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
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"]
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Check if NetworkInterfaces is specified with multiple ENIs
	network_interfaces := helpers.get_property(resource, "NetworkInterfaces", [])
	count(network_interfaces) > 1

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NetworkInterfaces"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Count NetworkInterfaceAttachment resources that reference this instance
	attachment_count := count([att_name |
		some att_name, att_resource in helpers.resources_by_type("ALIYUN::ECS::NetworkInterfaceAttachment")
		instance_id := helpers.get_property(att_resource, "InstanceId", "")
		helpers.is_referencing(instance_id, name)
	])

	# If more than one attachment references this instance, it's a violation
	attachment_count > 1

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])

	# Count NetworkInterfaceAttachment resources that reference this instance via GetAtt
	attachment_count := count([att_name |
		some att_name, att_resource in helpers.resources_by_type("ALIYUN::ECS::NetworkInterfaceAttachment")
		instance_id := helpers.get_property(att_resource, "InstanceId", "")
		helpers.is_get_att_referencing(instance_id, name)
	])

	# If more than one attachment references this instance, it's a violation
	attachment_count > 1

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
