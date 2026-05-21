package infraguard.rules.terraform.slb_no_public_ip

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-no-public-ip",
	"severity": "medium",
	"name": {
		"en": "SLB Instance No Public IP",
		"zh": "SLB 实例未开启公网访问",
		"ja": "SLB インスタンスにパブリック IP がない",
		"de": "SLB-Instanz Keine öffentliche IP",
		"es": "Instancia SLB Sin IP Pública",
		"fr": "Instance SLB Sans IP Publique",
		"pt": "Instância SLB Sem IP Público"
	},
	"description": {
		"en": "SLB instances should not have public IP addresses to reduce attack surface.",
		"zh": "SLB 实例网络类型为内网，视为合规。",
		"ja": "SLB インスタンスは攻撃面を減らすためにパブリック IP アドレスを持つべきではありません。",
		"de": "SLB-Instanzen sollten keine öffentlichen IP-Adressen haben, um die Angriffsfläche zu reduzieren.",
		"es": "Las instancias SLB no deben tener direcciones IP públicas para reducir la superficie de ataque.",
		"fr": "Les instances SLB ne doivent pas avoir d'adresses IP publiques pour réduire la surface d'attaque.",
		"pt": "As instâncias SLB não devem ter endereços IP públicos para reduzir a superfície de ataque."
	},
	"reason": {
		"en": "Publicly accessible SLB instances increase the attack surface and may expose services to unwanted internet traffic.",
		"zh": "可公开访问的 SLB 实例增加了攻击面，可能将服务暴露给非预期的互联网流量。",
		"ja": "パブリックアクセス可能な SLB インスタンスは攻撃面を増加させ、サービスを不要なインターネットトラフィックにさらす可能性があります。",
		"de": "Öffentlich zugängliche SLB-Instanzen erhöhen die Angriffsfläche und können Dienste unerwünschtem Internetverkehr aussetzen.",
		"es": "Las instancias SLB accesibles públicamente aumentan la superficie de ataque y pueden exponer servicios a tráfico de Internet no deseado.",
		"fr": "Les instances SLB accessibles publiquement augmentent la surface d'attaque et peuvent exposer les services à un trafic Internet indésirable.",
		"pt": "Instâncias SLB acessíveis publicamente aumentam a superfície de ataque e podem expor serviços a tráfego indesejado da Internet."
	},
	"recommendation": {
		"en": "Set address_type to \"intranet\" for internal services.",
		"zh": "对内部服务将 address_type 设置为 \"intranet\"。",
		"ja": "内部サービスの場合、address_type を \"intranet\" に設定します。",
		"de": "Setzen Sie address_type auf \"intranet\" für interne Dienste.",
		"es": "Establezca address_type en \"intranet\" para servicios internos.",
		"fr": "Définissez address_type sur \"intranet\" pour les services internes.",
		"pt": "Defina address_type como \"intranet\" para serviços internos."
	},
	"resource_types": ["alicloud_slb_load_balancer"],
	"iac_type": "terraform"
}

is_internal(resource) if {
	value := tf.get_attribute(resource, "address_type", "")
	not tf.is_unknown(value)
	value == "intranet"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_load_balancer")
	not is_internal(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_load_balancer.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
