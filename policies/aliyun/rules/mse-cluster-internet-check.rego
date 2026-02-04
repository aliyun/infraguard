package infraguard.rules.aliyun.mse_cluster_internet_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mse-cluster-internet-check",
	"severity": "high",
	"name": {
		"en": "MSE Cluster Has No Public Internet Access",
		"zh": "MSE 集群公网检测",
		"ja": "MSE クラスターにパブリックインターネットアクセスがない",
		"de": "MSE-Cluster hat keinen öffentlichen Internetzugriff",
		"es": "El Clúster MSE No Tiene Acceso Público a Internet",
		"fr": "Le Cluster MSE N'a Pas d'Accès Internet Public",
		"pt": "O Cluster MSE Não Tem Acesso Público à Internet"
	},
	"description": {
		"en": "Ensures that MSE clusters do not have public internet access enabled.",
		"zh": "确保 MSE 集群未开放公网访问。",
		"ja": "MSE クラスターでパブリックインターネットアクセスが有効になっていないことを確認します。",
		"de": "Stellt sicher, dass MSE-Cluster keinen öffentlichen Internetzugriff aktiviert haben.",
		"es": "Garantiza que los clústeres MSE no tengan acceso público a Internet habilitado.",
		"fr": "Garantit que les clusters MSE n'ont pas d'accès Internet public activé.",
		"pt": "Garante que os clusters MSE não tenham acesso público à Internet habilitado."
	},
	"reason": {
		"en": "Public internet access increases the attack surface and security risks for the cluster.",
		"zh": "公网访问增加了集群的攻击面和安全风险。",
		"ja": "パブリックインターネットアクセスは、クラスターの攻撃面とセキュリティリスクを増加させます。",
		"de": "Öffentlicher Internetzugriff erhöht die Angriffsfläche und Sicherheitsrisiken für den Cluster.",
		"es": "El acceso público a Internet aumenta la superficie de ataque y los riesgos de seguridad del clúster.",
		"fr": "L'accès Internet public augmente la surface d'attaque et les risques de sécurité pour le cluster.",
		"pt": "O acesso público à Internet aumenta a superfície de ataque e os riscos de segurança do cluster."
	},
	"recommendation": {
		"en": "Configure the MSE cluster to use private network access only.",
		"zh": "配置 MSE 集群仅使用内网访问。",
		"ja": "MSE クラスターをプライベートネットワークアクセスのみを使用するように設定します。",
		"de": "Konfigurieren Sie den MSE-Cluster so, dass nur privater Netzwerkzugriff verwendet wird.",
		"es": "Configure el clúster MSE para usar solo acceso de red privada.",
		"fr": "Configurez le cluster MSE pour utiliser uniquement l'accès réseau privé.",
		"pt": "Configure o cluster MSE para usar apenas acesso de rede privada."
	},
	"resource_types": ["ALIYUN::MSE::Cluster"]
}

# Check if cluster has public internet access
has_public_internet(resource) if {
	net_type := helpers.get_property(resource, "NetType", "privatenet")
	net_type == "pubnet"
}

has_public_internet(resource) if {
	pub_network_flow := helpers.get_property(resource, "PubNetworkFlow", 0)
	pub_network_flow > 0
}

has_public_internet(resource) if {
	connection_type := helpers.get_property(resource, "ConnectionType", "")
	connection_type == "single_eni"
	eip_enabled := helpers.get_property(resource, "EipEnabled", false)
	helpers.is_true(eip_enabled)
}

is_compliant(resource) if {
	not has_public_internet(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	has_public_internet(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NetType"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
