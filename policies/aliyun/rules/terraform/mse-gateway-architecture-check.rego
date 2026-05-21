package infraguard.rules.terraform.mse_gateway_architecture_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "MSE gateway should have replica > 1 for high availability.",
		"zh": "MSE 网关的 replica 应大于 1 以实现高可用。",
		"ja": "MSE（マイクロサービスエンジン）ゲートウェイが高可用性のために 1 つ以上のノードを持つことを確認します。",
		"de": "Stellt sicher, dass MSE (Microservice Engine)-Gateways mehr als 1 Knoten für hohe Verfügbarkeit haben.",
		"es": "Garantiza que las puertas de enlace MSE (Motor de Microservicios) tengan más de 1 nodo para alta disponibilidad.",
		"fr": "Garantit que les passerelles MSE (Moteur de Microservices) ont plus d'un nœud pour une haute disponibilité.",
		"pt": "Garante que os gateways MSE (Motor de Microserviços) tenham mais de 1 nó para alta disponibilidade."
	},
	"reason": {
		"en": "The MSE gateway replica count is not greater than 1.",
		"zh": "MSE 网关的 replica 数量未大于 1。",
		"ja": "単一ノードゲートウェイは単一障害点を作成し、サービス中断を引き起こす可能性があります。",
		"de": "Einzelknoten-Gateways erstellen einen Single Point of Failure und können zu Serviceunterbrechungen führen.",
		"es": "Las puertas de enlace de nodo único crean un punto único de falla y pueden causar interrupción del servicio.",
		"fr": "Les passerelles à nœud unique créent un point de défaillance unique et peuvent causer une interruption de service.",
		"pt": "Gateways de nó único criam um ponto único de falha e podem causar interrupção do serviço."
	},
	"recommendation": {
		"en": "Set replica to greater than 1 for high availability.",
		"zh": "将 replica 设置为大于 1 以实现高可用。",
		"ja": "MSE ゲートウェイを少なくとも 2 つのノードで設定します。",
		"de": "Konfigurieren Sie das MSE-Gateway mit mindestens 2 Knoten.",
		"es": "Configure la puerta de enlace MSE con al menos 2 nodos.",
		"fr": "Configurez la passerelle MSE avec au moins 2 nœuds.",
		"pt": "Configure o gateway MSE com pelo menos 2 nós."
	},
	"resource_types": ["alicloud_mse_gateway"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_gateway")
	replica := tf.get_attribute(resource, "replica", 0)
	replica <= 1
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_gateway.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
