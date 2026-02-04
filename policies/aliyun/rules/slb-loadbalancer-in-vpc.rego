package infraguard.rules.aliyun.slb_loadbalancer_in_vpc

import data.infraguard.helpers
import rego.v1

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
		"en": "Create SLB instances within a VPC.",
		"zh": "在 VPC 内创建 SLB 实例。",
		"ja": "VPC 内に SLB インスタンスを作成します。",
		"de": "Erstellen Sie SLB-Instanzen innerhalb eines VPC.",
		"es": "Cree instancias SLB dentro de un VPC.",
		"fr": "Créez des instances SLB dans un VPC.",
		"pt": "Crie instâncias SLB dentro de um VPC."
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"]
}

is_compliant(resource) if {
	helpers.has_property(resource, "VpcId")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcId"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
