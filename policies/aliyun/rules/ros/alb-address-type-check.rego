package infraguard.rules.aliyun.alb_address_type_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "alb-address-type-check",
	"severity": "low",
	"name": {
		"en": "ALB Address Type Check",
		"zh": "ALB 网络类型核查",
		"ja": "ALB アドレスタイプチェック",
		"de": "ALB-Adresstyp-Prüfung",
		"es": "Verificación de Tipo de Dirección ALB",
		"fr": "Vérification du Type d'Adresse ALB",
		"pt": "Verificação de Tipo de Endereço ALB"
	},
	"description": {
		"en": "Ensures ALB instances use the preferred address type (e.g., Intranet).",
		"zh": "确保 ALB 实例使用首选的网络类型（如私网）。",
		"ja": "ALB インスタンスが優先アドレスタイプ（例：Intranet）を使用することを確認します。",
		"de": "Stellt sicher, dass ALB-Instanzen den bevorzugten Adresstyp (z. B. Intranet) verwenden.",
		"es": "Garantiza que las instancias ALB usen el tipo de dirección preferido (por ejemplo, Intranet).",
		"fr": "Garantit que les instances ALB utilisent le type d'adresse préféré (par exemple, Intranet).",
		"pt": "Garante que as instâncias ALB usem o tipo de endereço preferido (por exemplo, Intranet)."
	},
	"reason": {
		"en": "Internal-only services should be placed on an Intranet ALB to reduce exposure.",
		"zh": "仅限内部使用的服务应放置在私网 ALB 上以减少暴露。",
		"ja": "内部専用サービスは、露出を減らすために Intranet ALB に配置する必要があります。",
		"de": "Nur interne Dienste sollten auf einem Intranet-ALB platziert werden, um die Exposition zu reduzieren.",
		"es": "Los servicios solo internos deben colocarse en un ALB de Intranet para reducir la exposición.",
		"fr": "Les services uniquement internes doivent être placés sur un ALB Intranet pour réduire l'exposition.",
		"pt": "Serviços apenas internos devem ser colocados em um ALB Intranet para reduzir a exposição."
	},
	"recommendation": {
		"en": "Set AddressType to 'Intranet' for internal services.",
		"zh": "为内部服务将 AddressType 设置为 'Intranet'。",
		"ja": "内部サービスの AddressType を 'Intranet' に設定します。",
		"de": "Setzen Sie AddressType für interne Dienste auf 'Intranet'.",
		"es": "Establezca AddressType en 'Intranet' para servicios internos.",
		"fr": "Définissez AddressType sur 'Intranet' pour les services internes.",
		"pt": "Defina AddressType como 'Intranet' para serviços internos."
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"]
}

is_compliant(resource) if {
	# Example: check if it's Intranet
	helpers.get_property(resource, "AddressType", "") == "Intranet"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AddressType"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
