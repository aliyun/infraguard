package infraguard.rules.terraform.vswitch_available_ip_count

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "vswitch-available-ip-count",
	"severity": "medium",
	"name": {
		"en": "VSwitch Available IP Count Check",
		"zh": "VSwitch 可用 IP 数量检测",
		"ja": "VSwitch 利用可能 IP 数チェック",
		"de": "VSwitch Verfügbare IP-Anzahlprüfung",
		"es": "Verificación de Conteo de IP Disponibles de VSwitch",
		"fr": "Vérification du Nombre d'IP Disponibles VSwitch",
		"pt": "Verificação de Contagem de IP Disponível do VSwitch"
	},
	"description": {
		"en": "Ensures that the VSwitch has a sufficient number of available IP addresses.",
		"zh": "确保 VSwitch 具有足够数量的可用 IP 地址。",
		"ja": "VSwitch に十分な数の利用可能な IP アドレスがあることを確認します。",
		"de": "Stellt sicher, dass der VSwitch eine ausreichende Anzahl verfügbarer IP-Adressen hat.",
		"es": "Garantiza que el VSwitch tenga un número suficiente de direcciones IP disponibles.",
		"fr": "Garantit que le VSwitch a un nombre suffisant d'adresses IP disponibles.",
		"pt": "Garante que o VSwitch tenha um número suficiente de endereços IP disponíveis."
	},
	"reason": {
		"en": "Running out of available IP addresses prevents new resources from being created in the VSwitch.",
		"zh": "可用 IP 地址耗尽将阻止在 VSwitch 中创建新资源。",
		"ja": "利用可能な IP アドレスが不足すると、VSwitch で新しいリソースを作成できなくなります。",
		"de": "Das Ausgehen verfügbarer IP-Adressen verhindert die Erstellung neuer Ressourcen im VSwitch.",
		"es": "Agotar las direcciones IP disponibles impide crear nuevos recursos en el VSwitch.",
		"fr": "L'épuisement des adresses IP disponibles empêche la création de nouvelles ressources dans le VSwitch.",
		"pt": "Esgotar os endereços IP disponíveis impede a criação de novos recursos no VSwitch."
	},
	"recommendation": {
		"en": "Use a cidr_block with a prefix length smaller than /29 to ensure sufficient available IP addresses.",
		"zh": "使用前缀长度小于 /29 的 cidr_block 以确保有足够的可用 IP 地址。",
		"ja": "十分な利用可能な IP アドレスを確保するために、/29 より小さいプレフィックス長の cidr_block を使用します。",
		"de": "Verwenden Sie einen cidr_block mit einer Präfixlänge kleiner als /29, um genügend verfügbare IP-Adressen sicherzustellen.",
		"es": "Use un cidr_block con una longitud de prefijo menor que /29 para asegurar suficientes direcciones IP disponibles.",
		"fr": "Utilisez un cidr_block avec une longueur de préfixe inférieure à /29 pour garantir suffisamment d'adresses IP disponibles.",
		"pt": "Use um cidr_block com comprimento de prefixo menor que /29 para garantir endereços IP disponíveis suficientes."
	},
	"resource_types": ["alicloud_vswitch"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_vswitch")
	cidr := tf.get_attribute(resource, "cidr_block", "")
	not tf.is_unknown(cidr)
	endswith(cidr, "/29")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_vswitch.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
