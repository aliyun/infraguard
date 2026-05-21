package infraguard.rules.terraform.mse_cluster_internet_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "MSE cluster should not be exposed to the public internet. net_type should not be 'pubnet' and pub_network_flow should not be greater than 0.",
		"zh": "MSE 集群不应暴露在公网。net_type 不应为 'pubnet'，且 pub_network_flow 不应大于 0。",
		"ja": "MSE クラスターでパブリックインターネットアクセスが有効になっていないことを確認します。",
		"de": "Stellt sicher, dass MSE-Cluster keinen öffentlichen Internetzugriff aktiviert haben.",
		"es": "Garantiza que los clústeres MSE no tengan acceso público a Internet habilitado.",
		"fr": "Garantit que les clusters MSE n'ont pas d'accès Internet public activé.",
		"pt": "Garante que os clusters MSE não tenham acesso público à Internet habilitado."
	},
	"reason": {
		"en": "The MSE cluster is exposed to the public internet.",
		"zh": "MSE 集群暴露在公网中。",
		"ja": "パブリックインターネットアクセスは、クラスターの攻撃面とセキュリティリスクを増加させます。",
		"de": "Öffentlicher Internetzugriff erhöht die Angriffsfläche und Sicherheitsrisiken für den Cluster.",
		"es": "El acceso público a Internet aumenta la superficie de ataque y los riesgos de seguridad del clúster.",
		"fr": "L'accès Internet public augmente la surface d'attaque et les risques de sécurité pour le cluster.",
		"pt": "O acesso público à Internet aumenta a superfície de ataque e os riscos de segurança do cluster."
	},
	"recommendation": {
		"en": "Set net_type to 'privatenet' and ensure pub_network_flow is '0' or not set.",
		"zh": "将 net_type 设置为 'privatenet'，并确保 pub_network_flow 为 '0' 或未设置。",
		"ja": "MSE クラスターをプライベートネットワークアクセスのみを使用するように設定します。",
		"de": "Konfigurieren Sie den MSE-Cluster so, dass nur privater Netzwerkzugriff verwendet wird.",
		"es": "Configure el clúster MSE para usar solo acceso de red privada.",
		"fr": "Configurez le cluster MSE pour utiliser uniquement l'accès réseau privé.",
		"pt": "Configure o cluster MSE para usar apenas acesso de rede privada."
	},
	"resource_types": ["alicloud_mse_cluster"],
	"iac_type": "terraform"
}

is_public_net_type(resource) if {
	net_type := tf.get_attribute(resource, "net_type", "")
	net_type == "pubnet"
}

has_public_network_flow(resource) if {
	pub_network_flow := tf.get_attribute(resource, "pub_network_flow", "0")
	pub_network_flow != "0"
	pub_network_flow != 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_cluster")
	is_public_net_type(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_cluster")
	has_public_network_flow(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
