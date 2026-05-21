package infraguard.rules.aliyun.eip_bandwidth_limit

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "eip-bandwidth-limit",
	"severity": "low",
	"name": {
		"en": "EIP Bandwidth Limit",
		"zh": "EIP 带宽上限核查",
		"ja": "EIP 帯域幅制限",
		"de": "EIP-Bandbreitenlimit",
		"es": "Límite de Ancho de Banda EIP",
		"fr": "Limite de Bande Passante EIP",
		"pt": "Limite de Largura de Banda EIP"
	},
	"description": {
		"en": "Ensures EIP bandwidth does not exceed a specified maximum value.",
		"zh": "确保 EIP 带宽不超过指定的最高值。",
		"ja": "EIP 帯域幅が指定された最大値を超えないことを確認します。",
		"de": "Stellt sicher, dass die EIP-Bandbreite einen angegebenen Maximalwert nicht überschreitet.",
		"es": "Garantiza que el ancho de banda EIP no exceda un valor máximo especificado.",
		"fr": "Garantit que la bande passante EIP ne dépasse pas une valeur maximale spécifiée.",
		"pt": "Garante que a largura de banda EIP não exceda um valor máximo especificado."
	},
	"reason": {
		"en": "Excessive bandwidth settings can lead to higher than expected costs.",
		"zh": "过高的带宽设置可能导致超出预期的成本。",
		"ja": "過剰な帯域幅設定により、予想以上のコストが発生する可能性があります。",
		"de": "Übermäßige Bandbreiteneinstellungen können zu höheren als erwarteten Kosten führen.",
		"es": "Las configuraciones de ancho de banda excesivas pueden llevar a costos más altos de lo esperado.",
		"fr": "Des paramètres de bande passante excessifs peuvent entraîner des coûts plus élevés que prévu.",
		"pt": "Configurações excessivas de largura de banda podem levar a custos mais altos do que o esperado."
	},
	"recommendation": {
		"en": "Set EIP bandwidth to a reasonable value (e.g., up to 100Mbps).",
		"zh": "将 EIP 带宽设置为合理的值（如不超过 100Mbps）。",
		"ja": "EIP 帯域幅を合理的な値（例：100Mbps まで）に設定します。",
		"de": "Setzen Sie die EIP-Bandbreite auf einen angemessenen Wert (z. B. bis zu 100 Mbps).",
		"es": "Establezca el ancho de banda EIP en un valor razonable (por ejemplo, hasta 100 Mbps).",
		"fr": "Définissez la bande passante EIP à une valeur raisonnable (par exemple, jusqu'à 100 Mbps).",
		"pt": "Defina a largura de banda EIP para um valor razoável (por exemplo, até 100 Mbps)."
	},
	"resource_types": ["ALIYUN::VPC::EIP"]
}

is_compliant(resource) if {
	bandwidth := helpers.get_property(resource, "Bandwidth", 5)
	bandwidth <= 100
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::EIP")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Bandwidth"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
