package infraguard.rules.terraform.slb_loadbalancer_in_vpc

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-loadbalancer-in-vpc",
	"severity": "medium",
	"name": {
		"en": "SLB in VPC Check",
		"zh": "强制 SLB 部署在 VPC 环境中",
		"ja": "VPC チェック内の SLB",
		"de": "SLB im VPC Prüfung",
		"es": "Verificación SLB en VPC",
		"fr": "Vérification SLB dans VPC",
		"pt": "Verificação SLB em VPC"
	},
	"description": {
		"en": "Ensures SLB instances are deployed within a Virtual Private Cloud (VPC).",
		"zh": "确保 SLB 实例部署在专有网络（VPC）中。",
		"ja": "SLB インスタンスが Virtual Private Cloud（VPC）内に展開されていることを確認します。",
		"de": "Stellt sicher, dass SLB-Instanzen innerhalb eines Virtual Private Cloud (VPC) bereitgestellt werden.",
		"es": "Garantiza que las instancias SLB estén desplegadas dentro de una Virtual Private Cloud (VPC).",
		"fr": "Garantit que les instances SLB sont déployées dans un Virtual Private Cloud (VPC).",
		"pt": "Garante que as instâncias SLB estejam implantadas dentro de uma Virtual Private Cloud (VPC)."
	},
	"reason": {
		"en": "Classic network is deprecated and offers less security and isolation than VPC.",
		"zh": "经典网络已弃用，其安全性和隔离性均不如 VPC。",
		"ja": "クラシックネットワークは非推奨であり、VPC よりもセキュリティと分離が少なくなります。",
		"de": "Das klassische Netzwerk ist veraltet und bietet weniger Sicherheit und Isolation als VPC.",
		"es": "La red clásica está deprecada y ofrece menos seguridad y aislamiento que VPC.",
		"fr": "Le réseau classique est déprécié et offre moins de sécurité et d'isolation que VPC.",
		"pt": "A rede clássica está depreciada e oferece menos segurança e isolamento do que VPC."
	},
	"recommendation": {
		"en": "Set vswitch_id to deploy the SLB instance within a VPC.",
		"zh": "设置 vswitch_id 将 SLB 实例部署在 VPC 中。",
		"ja": "vswitch_id を設定して SLB インスタンスを VPC 内に展開します。",
		"de": "Setzen Sie vswitch_id, um die SLB-Instanz innerhalb eines VPC bereitzustellen.",
		"es": "Establezca vswitch_id para desplegar la instancia SLB dentro de un VPC.",
		"fr": "Définissez vswitch_id pour déployer l'instance SLB dans un VPC.",
		"pt": "Defina vswitch_id para implantar a instância SLB dentro de um VPC."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

is_in_vpc(resource) if {
	value := tf.get_attribute(resource, "vswitch_id", "")
	not tf.is_unknown(value)
	value != ""
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_in_vpc(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
