package infraguard.rules.aliyun.slb_loadbalancer_bandwidth_limit

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-loadbalancer-bandwidth-limit",
	"severity": "low",
	"name": {
		"en": "SLB Bandwidth Limit",
		"zh": "SLB 带宽上限核查",
		"ja": "SLB 帯域幅制限",
		"de": "SLB-Bandbreitenlimit",
		"es": "Límite de Ancho de Banda SLB",
		"fr": "Limite de Bande Passante SLB",
		"pt": "Limite de Largura de Banda SLB"
	},
	"description": {
		"en": "Ensures SLB instance bandwidth does not exceed a specified maximum value.",
		"zh": "确保 SLB 实例带宽不超过指定的最高值。",
		"ja": "SLB インスタンスの帯域幅が指定された最大値を超えないことを確認します。",
		"de": "Stellt sicher, dass die Bandbreite der SLB-Instanz einen angegebenen Maximalwert nicht überschreitet.",
		"es": "Garantiza que el ancho de banda de la instancia SLB no exceda un valor máximo especificado.",
		"fr": "Garantit que la bande passante de l'instance SLB ne dépasse pas une valeur maximale spécifiée.",
		"pt": "Garante que a largura de banda da instância SLB não exceda um valor máximo especificado."
	},
	"reason": {
		"en": "Controlling SLB bandwidth helps manage network costs.",
		"zh": "控制 SLB 带宽有助于管理网络成本。",
		"ja": "SLB 帯域幅を制御することで、ネットワークコストの管理に役立ちます。",
		"de": "Die Kontrolle der SLB-Bandbreite hilft bei der Verwaltung der Netzwerkkosten.",
		"es": "Controlar el ancho de banda SLB ayuda a gestionar los costos de red.",
		"fr": "Le contrôle de la bande passante SLB aide à gérer les coûts réseau.",
		"pt": "Controlar a largura de banda do SLB ajuda a gerenciar os custos de rede."
	},
	"recommendation": {
		"en": "Set SLB bandwidth to a reasonable value (e.g., up to 500Mbps).",
		"zh": "将 SLB 带宽设置为合理的值（如不超过 500Mbps）。",
		"ja": "SLB 帯域幅を合理的な値（例：500Mbps まで）に設定します。",
		"de": "Setzen Sie die SLB-Bandbreite auf einen angemessenen Wert (z. B. bis zu 500 Mbps).",
		"es": "Establezca el ancho de banda SLB en un valor razonable (por ejemplo, hasta 500 Mbps).",
		"fr": "Définissez la bande passante SLB à une valeur raisonnable (par exemple, jusqu'à 500 Mbps).",
		"pt": "Defina a largura de banda do SLB para um valor razoável (por exemplo, até 500 Mbps)."
	},
	"resource_types": ["ALIYUN::SLB::LoadBalancer"]
}

is_compliant(resource) if {
	bandwidth := helpers.get_property(resource, "Bandwidth", 1)
	bandwidth <= 500
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::LoadBalancer")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Bandwidth"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
