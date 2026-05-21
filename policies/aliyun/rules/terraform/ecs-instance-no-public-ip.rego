package infraguard.rules.terraform.ecs_instance_no_public_ip

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ecs-instance-no-public-ip",
	"severity": "high",
	"name": {
		"en": "ECS instance should not bind public IP",
		"zh": "ECS 实例禁止绑定公网地址",
		"ja": "ECS インスタンスはパブリック IP をバインドすべきではない",
		"de": "ECS-Instanz sollte keine öffentliche IP binden",
		"es": "La Instancia ECS No Debe Vincular IP Pública",
		"fr": "L'Instance ECS Ne Doit Pas Lier d'IP Publique",
		"pt": "Instância ECS Não Deve Vincular IP Público"
	},
	"description": {
		"en": "ECS instances should not directly bind IPv4 public IP or Elastic IP, considered compliant.",
		"zh": "ECS 实例没有直接绑定 IPv4 公网 IP 或弹性公网 IP，视为合规。",
		"ja": "ECS インスタンスは IPv4 パブリック IP または Elastic IP を直接バインドすべきではなく、準拠と見なされます。",
		"de": "ECS-Instanzen sollten keine IPv4-öffentliche IP oder Elastic IP direkt binden, was als konform gilt.",
		"es": "Las instancias ECS no deben vincular directamente IP pública IPv4 o IP elástica, considerado conforme.",
		"fr": "Les instances ECS ne doivent pas lier directement d'IP publique IPv4 ou d'IP élastique, considéré comme conforme.",
		"pt": "As instâncias ECS não devem vincular diretamente IP público IPv4 ou IP elástico, considerado conforme."
	},
	"reason": {
		"en": "ECS instance has a public IP bound",
		"zh": "ECS 实例绑定了公网地址",
		"ja": "ECS インスタンスにパブリック IP がバインドされています",
		"de": "ECS-Instanz hat eine öffentliche IP gebunden",
		"es": "La instancia ECS tiene una IP pública vinculada",
		"fr": "L'instance ECS a une IP publique liée",
		"pt": "A instância ECS tem um IP público vinculado"
	},
	"recommendation": {
		"en": "Use NAT Gateway or SLB for internet access instead of direct public IP binding",
		"zh": "使用 NAT 网关或 SLB 进行互联网访问，而不是直接绑定公网 IP",
		"ja": "直接パブリック IP バインディングの代わりに、インターネットアクセスに NAT ゲートウェイまたは SLB を使用します",
		"de": "Verwenden Sie NAT Gateway oder SLB für Internetzugriff anstelle der direkten Bindung öffentlicher IP",
		"es": "Use NAT Gateway o SLB para acceso a Internet en lugar de vinculación directa de IP pública",
		"fr": "Utilisez NAT Gateway ou SLB pour l'accès Internet au lieu de la liaison directe d'IP publique",
		"pt": "Use NAT Gateway ou SLB para acesso à Internet em vez de vinculação direta de IP público"
	},
	"resource_types": ["alicloud_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	allocate_public_ip := tf.get_attribute(resource, "allocate_public_ip", false)
	not tf.is_unknown(allocate_public_ip)
	allocate_public_ip == true
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	bandwidth := tf.get_attribute(resource, "internet_max_bandwidth_out", 0)
	not tf.is_unknown(bandwidth)
	bandwidth > 0
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_instance")
	some _, eip_assoc in tf.resources_by_type("alicloud_eip_association")
	instance_id := tf.get_attribute(eip_assoc, "instance_id", "")
	instance_id == name
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_instance.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
