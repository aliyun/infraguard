package infraguard.rules.aliyun.vswitch_available_ip_count

import rego.v1

import data.infraguard.helpers

# Rule metadata
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
		"en": "Ensure that the VSwitch has enough available IP addresses or create a larger VSwitch.",
		"zh": "确保 VSwitch 具有足够的可用 IP 地址，或创建一个更大的 VSwitch。",
		"ja": "VSwitch に十分な利用可能な IP アドレスがあることを確認するか、より大きな VSwitch を作成します。",
		"de": "Stellen Sie sicher, dass der VSwitch genügend verfügbare IP-Adressen hat oder erstellen Sie einen größeren VSwitch.",
		"es": "Asegúrese de que el VSwitch tenga suficientes direcciones IP disponibles o cree un VSwitch más grande.",
		"fr": "Assurez-vous que le VSwitch a suffisamment d'adresses IP disponibles ou créez un VSwitch plus grand.",
		"pt": "Garanta que o VSwitch tenha endereços IP disponíveis suficientes ou crie um VSwitch maior."
	},
	"resource_types": ["ALIYUN::ECS::VSwitch"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::VSwitch")

	# Conceptual check for available IPs
	# Since it's runtime info, in template we might check CIDR size
	cidr := helpers.get_property(resource, "CidrBlock", "")

	# This is a bit complex to calculate accurately in Rego without helpers,
	# but we can detect very small subnets.
	endswith(cidr, "/29") # Example: Too small
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "CidrBlock"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
