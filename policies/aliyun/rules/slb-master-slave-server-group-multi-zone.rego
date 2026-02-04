package infraguard.rules.aliyun.slb_master_slave_server_group_multi_zone

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-master-slave-server-group-multi-zone",
	"severity": "medium",
	"name": {
		"en": "SLB Master-Slave Server Group Multi-Zone",
		"zh": "SLB 负载均衡主备服务器组添加多个可用区资源",
		"ja": "SLB マスタースレーブサーバーグループのマルチゾーン",
		"de": "SLB Master-Slave-Server-Gruppe Multi-Zone",
		"es": "Grupo de Servidores Maestro-Esclavo SLB Multi-Zona",
		"fr": "Groupe de Serveurs Maître-Esclave SLB Multi-Zone",
		"pt": "Grupo de Servidores Mestre-Escravo SLB Multi-Zona"
	},
	"description": {
		"en": "The master-slave server group of SLB instances should have resources distributed across multiple availability zones.",
		"zh": "SLB 负载均衡的主备服务器组挂载资源分布在多个可用区，视为合规。主备服务器组无挂载任何资源时不适用本规则，视为不适用。",
		"ja": "SLB インスタンスのマスタースレーブサーバーグループは、リソースを複数の可用性ゾーンに分散させる必要があります。",
		"de": "Die Master-Slave-Server-Gruppe von SLB-Instanzen sollte Ressourcen über mehrere Verfügbarkeitszonen verteilt haben.",
		"es": "El grupo de servidores maestro-esclavo de las instancias SLB debe tener recursos distribuidos en múltiples zonas de disponibilidad.",
		"fr": "Le groupe de serveurs maître-esclave des instances SLB doit avoir des ressources distribuées sur plusieurs zones de disponibilité.",
		"pt": "O grupo de servidores mestre-escravo das instâncias SLB deve ter recursos distribuídos em múltiplas zonas de disponibilidade."
	},
	"reason": {
		"en": "Single-zone master-slave servers create a single point of failure and reduce availability.",
		"zh": "单可用区主备服务器创建单点故障并降低可用性。",
		"ja": "単一ゾーンのマスタースレーブサーバーは単一障害点を作成し、可用性を低下させます。",
		"de": "Einzelzonen-Master-Slave-Server erstellen einen Single Point of Failure und reduzieren die Verfügbarkeit.",
		"es": "Los servidores maestro-esclavo de zona única crean un punto único de falla y reducen la disponibilidad.",
		"fr": "Les serveurs maître-esclave à zone unique créent un point de défaillance unique et réduisent la disponibilité.",
		"pt": "Servidores mestre-escravo de zona única criam um ponto único de falha e reduzem a disponibilidade."
	},
	"recommendation": {
		"en": "Distribute master and slave servers across different availability zones.",
		"zh": "将主服务器和从服务器分布在不同的可用区。",
		"ja": "マスターサーバーとスレーブサーバーを異なる可用性ゾーンに分散します。",
		"de": "Verteilen Sie Master- und Slave-Server über verschiedene Verfügbarkeitszonen.",
		"es": "Distribuya los servidores maestro y esclavo en diferentes zonas de disponibilidad.",
		"fr": "Répartissez les serveurs maître et esclave sur différentes zones de disponibilité.",
		"pt": "Distribua servidores mestre e escravo em diferentes zonas de disponibilidade."
	},
	"resource_types": ["ALIYUN::SLB::MasterSlaveServerGroup"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::MasterSlaveServerGroup")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
