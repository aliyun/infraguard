package infraguard.rules.aliyun.emr_cluster_master_public_access_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "emr-cluster-master-public-access-check",
	"severity": "medium",
	"name": {
		"en": "EMR Cluster Master Node Public Access Check",
		"zh": "EMR 集群 Master 节点公网开启检测",
		"ja": "EMR クラスターのマスターノードのパブリックアクセチェック",
		"de": "EMR-Cluster-Master-Knoten öffentlicher Zugriffsprüfung",
		"es": "Verificación de Acceso Público del Nodo Maestro del Clúster EMR",
		"fr": "Vérification de l'Accès Public du Nœud Maître du Cluster EMR",
		"pt": "Verificação de Acesso Público do Nó Mestre do Cluster EMR"
	},
	"description": {
		"en": "EMR on ECS cluster master nodes should not have public IP enabled.",
		"zh": "EMR on ECS 集群 Master 节点公网不开启，视为合规。",
		"ja": "EMR on ECS クラスターのマスターノードでパブリック IP を有効にしないでください。",
		"de": "EMR on ECS-Cluster-Master-Knoten sollten keine öffentliche IP aktiviert haben.",
		"es": "Los nodos maestros del clúster EMR en ECS no deben tener IP pública habilitada.",
		"fr": "Les nœuds maîtres du cluster EMR sur ECS ne doivent pas avoir d'IP publique activée.",
		"pt": "Os nós mestres do cluster EMR no ECS não devem ter IP público habilitado."
	},
	"reason": {
		"en": "EMR master nodes with public IP enabled may be exposed to the internet, increasing security risks.",
		"zh": "EMR Master 节点开启公网 IP 可能会暴露在互联网中，增加安全风险。",
		"ja": "パブリック IP が有効な EMR マスターノードはインターネットにさらされる可能性があり、セキュリティリスクが増加します。",
		"de": "EMR-Master-Knoten mit aktivierter öffentlicher IP können dem Internet ausgesetzt sein, was die Sicherheitsrisiken erhöht.",
		"es": "Los nodos maestros de EMR con IP pública habilitada pueden estar expuestos a internet, aumentando los riesgos de seguridad.",
		"fr": "Les nœuds maîtres EMR avec IP publique activée peuvent être exposés à Internet, augmentant les risques de sécurité.",
		"pt": "Nós mestres do EMR com IP público habilitado podem estar expostos à internet, aumentando os riscos de segurança."
	},
	"recommendation": {
		"en": "Set 'IsOpenPublicIp' to false for the EMR cluster and use a NAT gateway or bastion host for access.",
		"zh": "将 EMR 集群的'IsOpenPublicIp'属性设置为 false，并使用 NAT 网关或堡垒机进行访问。",
		"ja": "EMR クラスターの 'IsOpenPublicIp' を false に設定し、アクセスに NAT ゲートウェイまたはバスチオンホストを使用します。",
		"de": "Setzen Sie 'IsOpenPublicIp' für den EMR-Cluster auf false und verwenden Sie ein NAT-Gateway oder einen Bastion-Host für den Zugriff.",
		"es": "Establezca 'IsOpenPublicIp' en false para el clúster EMR y use una puerta de enlace NAT o un host bastión para el acceso.",
		"fr": "Définissez 'IsOpenPublicIp' sur false pour le cluster EMR et utilisez une passerelle NAT ou un hôte bastion pour l'accès.",
		"pt": "Defina 'IsOpenPublicIp' como false para o cluster EMR e use um gateway NAT ou host bastião para acesso."
	},
	"resource_types": ["ALIYUN::EMR::Cluster"]
}

# Deny if IsOpenPublicIp is true
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::EMR::Cluster")
	resource.Properties.IsOpenPublicIp == true

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IsOpenPublicIp"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
