package infraguard.rules.terraform.natgateway_eip_used_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "natgateway-eip-used-check",
	"severity": "medium",
	"name": {
		"en": "NAT Gateway Enhanced Type Check",
		"zh": "NAT 网关使用增强型以支持 EIP 分离",
		"ja": "NAT ゲートウェイ拡張タイプチェック",
		"de": "NAT-Gateway Erweiterter Typ Prüfung",
		"es": "Verificación de Tipo Mejorado de Puerta de Enlace NAT",
		"fr": "Vérification de Type Amélioré de Passerelle NAT",
		"pt": "Verificação de Tipo Aprimorado do Gateway NAT"
	},
	"description": {
		"en": "Ensures NAT gateways use the Enhanced type to support separate SNAT/DNAT EIP binding.",
		"zh": "确保 NAT 网关使用增强型以支持 SNAT/DNAT EIP 分离绑定。",
		"ja": "NAT ゲートウェイが SNAT/DNAT EIP の分離バインドをサポートするために拡張タイプを使用することを確認します。",
		"de": "Stellt sicher, dass NAT-Gateways den erweiterten Typ verwenden, um separate SNAT/DNAT EIP-Bindung zu unterstützen.",
		"es": "Garantiza que las puertas de enlace NAT usen el tipo Mejorado para soportar la vinculación separada de EIP SNAT/DNAT.",
		"fr": "Garantit que les passerelles NAT utilisent le type Amélioré pour prendre en charge la liaison EIP SNAT/DNAT séparée.",
		"pt": "Garante que os gateways NAT usem o tipo Aprimorado para suportar vinculação EIP SNAT/DNAT separada."
	},
	"reason": {
		"en": "Normal type NAT gateways do not support separate EIP binding for SNAT and DNAT, which may cause EIP conflicts.",
		"zh": "普通型 NAT 网关不支持 SNAT 和 DNAT 的 EIP 分离绑定，可能导致 EIP 冲突。",
		"ja": "通常タイプの NAT ゲートウェイは SNAT と DNAT の EIP 分離バインドをサポートしないため、EIP の競合が発生する可能性があります。",
		"de": "NAT-Gateways vom normalen Typ unterstützen keine separate EIP-Bindung für SNAT und DNAT, was zu EIP-Konflikten führen kann.",
		"es": "Las puertas de enlace NAT de tipo Normal no soportan la vinculación separada de EIP para SNAT y DNAT, lo que puede causar conflictos de EIP.",
		"fr": "Les passerelles NAT de type Normal ne prennent pas en charge la liaison EIP séparée pour SNAT et DNAT, ce qui peut entraîner des conflits EIP.",
		"pt": "Gateways NAT do tipo Normal não suportam vinculação EIP separada para SNAT e DNAT, o que pode causar conflitos de EIP."
	},
	"recommendation": {
		"en": "Set nat_type to 'Enhanced' to enable separate SNAT/DNAT EIP binding.",
		"zh": "将 nat_type 设置为 'Enhanced' 以启用 SNAT/DNAT EIP 分离绑定。",
		"ja": "nat_type を 'Enhanced' に設定して、SNAT/DNAT EIP の分離バインドを有効にします。",
		"de": "Setzen Sie nat_type auf 'Enhanced', um separate SNAT/DNAT EIP-Bindung zu ermöglichen.",
		"es": "Establezca nat_type en 'Enhanced' para habilitar la vinculación separada de EIP SNAT/DNAT.",
		"fr": "Définissez nat_type sur 'Enhanced' pour activer la liaison EIP SNAT/DNAT séparée.",
		"pt": "Defina nat_type como 'Enhanced' para habilitar vinculação EIP SNAT/DNAT separada."
	},
	"resource_types": ["alicloud_nat_gateway"],
	"iac_type": "terraform"
}

is_compliant(resource) if {
	nat_type := tf.get_attribute(resource, "nat_type", "")
	not tf.is_unknown(nat_type)
	nat_type == "Enhanced"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nat_gateway")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nat_gateway.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
