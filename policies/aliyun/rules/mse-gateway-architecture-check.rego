package infraguard.rules.aliyun.mse_gateway_architecture_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mse-gateway-architecture-check",
	"severity": "high",
	"name": {
		"en": "MSE Gateway Has Multiple Nodes",
		"zh": "MSE 云原生网关多节点检测",
		"ja": "MSE ゲートウェイに複数のノードがある",
		"de": "MSE-Gateway hat mehrere Knoten",
		"es": "La Puerta de Enlace MSE Tiene Múltiples Nodos",
		"fr": "La Passerelle MSE a Plusieurs Nœuds",
		"pt": "O Gateway MSE Tem Múltiplos Nós"
	},
	"description": {
		"en": "Ensures that MSE (Microservice Engine) gateways have more than 1 node for high availability.",
		"zh": "确保 MSE（微服务引擎）网关具有超过 1 个节点以实现高可用性。",
		"ja": "MSE（マイクロサービスエンジン）ゲートウェイが高可用性のために 1 つ以上のノードを持つことを確認します。",
		"de": "Stellt sicher, dass MSE (Microservice Engine)-Gateways mehr als 1 Knoten für hohe Verfügbarkeit haben.",
		"es": "Garantiza que las puertas de enlace MSE (Motor de Microservicios) tengan más de 1 nodo para alta disponibilidad.",
		"fr": "Garantit que les passerelles MSE (Moteur de Microservices) ont plus d'un nœud pour une haute disponibilité.",
		"pt": "Garante que os gateways MSE (Motor de Microserviços) tenham mais de 1 nó para alta disponibilidade."
	},
	"reason": {
		"en": "Single-node gateways create a single point of failure and may cause service interruption.",
		"zh": "单节点网关存在单点故障，可能导致服务中断。",
		"ja": "単一ノードゲートウェイは単一障害点を作成し、サービス中断を引き起こす可能性があります。",
		"de": "Einzelknoten-Gateways erstellen einen Single Point of Failure und können zu Serviceunterbrechungen führen.",
		"es": "Las puertas de enlace de nodo único crean un punto único de falla y pueden causar interrupción del servicio.",
		"fr": "Les passerelles à nœud unique créent un point de défaillance unique et peuvent causer une interruption de service.",
		"pt": "Gateways de nó único criam um ponto único de falha e podem causar interrupção do serviço."
	},
	"recommendation": {
		"en": "Configure the MSE gateway with at least 2 nodes.",
		"zh": "将 MSE 网关配置为至少 2 个节点。",
		"ja": "MSE ゲートウェイを少なくとも 2 つのノードで設定します。",
		"de": "Konfigurieren Sie das MSE-Gateway mit mindestens 2 Knoten.",
		"es": "Configure la puerta de enlace MSE con al menos 2 nodos.",
		"fr": "Configurez la passerelle MSE avec au moins 2 nœuds.",
		"pt": "Configure o gateway MSE com pelo menos 2 nós."
	},
	"resource_types": ["ALIYUN::MSE::Gateway"]
}

# Get node count from gateway
get_node_count(resource) := node_count if {
	# Use Replica property
	replica := helpers.get_property(resource, "Replica", 0)
	replica > 0
	node_count := replica
} else := node_count if {
	# Fall back to Nodes array
	nodes := helpers.get_property(resource, "Nodes", [])
	node_count := count(nodes)
}

# Check if gateway has more than 1 node
has_multi_nodes(resource) if {
	get_node_count(resource) > 1
}

is_compliant(resource) if {
	has_multi_nodes(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Gateway")
	not has_multi_nodes(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Replica"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
