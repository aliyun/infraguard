package infraguard.rules.aliyun.ecs_internetmaxbandwidth_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ecs-internetmaxbandwidth-check",
	"severity": "medium",
	"name": {
		"en": "ECS Internet Max Bandwidth Check",
		"zh": "ECS 公网出口带宽检查",
		"ja": "ECS インターネット最大帯域幅チェック",
		"de": "ECS-Internet Max-Bandbreitenprüfung",
		"es": "Verificación de Ancho de Banda Máximo de Internet ECS",
		"fr": "Vérification de la Bande Passante Internet Maximale ECS",
		"pt": "Verificação de Largura de Banda Máxima da Internet ECS"
	},
	"description": {
		"en": "Ensures ECS internet outbound bandwidth does not exceed specified limits.",
		"zh": "确保 ECS 公网出口带宽不超过指定限制。",
		"ja": "ECS インターネット送信帯域幅が指定された制限を超えないことを確認します。",
		"de": "Stellt sicher, dass die ausgehende Internet-Bandbreite von ECS die angegebenen Grenzwerte nicht überschreitet.",
		"es": "Garantiza que el ancho de banda saliente de Internet ECS no exceda los límites especificados.",
		"fr": "Garantit que la bande passante Internet sortante ECS ne dépasse pas les limites spécifiées.",
		"pt": "Garante que a largura de banda de saída da Internet ECS não exceda os limites especificados."
	},
	"reason": {
		"en": "High bandwidth settings can lead to unexpected costs and increased attack surface.",
		"zh": "高带宽设置可能导致意外成本增加并扩大攻击面。",
		"ja": "高い帯域幅設定は、予期しないコストの増加と攻撃面の拡大につながる可能性があります。",
		"de": "Hohe Bandbreiteneinstellungen können zu unerwarteten Kosten und einer erhöhten Angriffsfläche führen.",
		"es": "Las configuraciones de alto ancho de banda pueden provocar costos inesperados y una superficie de ataque aumentada.",
		"fr": "Les paramètres de bande passante élevée peuvent entraîner des coûts inattendus et une surface d'attaque accrue.",
		"pt": "Configurações de largura de banda alta podem levar a custos inesperados e aumento da superfície de ataque."
	},
	"recommendation": {
		"en": "Limit the InternetMaxBandwidthOut to a reasonable value (e.g., 100Mbps).",
		"zh": "将 InternetMaxBandwidthOut 限制在合理范围内（例如 100Mbps）。",
		"ja": "InternetMaxBandwidthOut を合理的な値（例：100Mbps）に制限します。",
		"de": "Begrenzen Sie InternetMaxBandwidthOut auf einen angemessenen Wert (z. B. 100 Mbps).",
		"es": "Limite InternetMaxBandwidthOut a un valor razonable (por ejemplo, 100 Mbps).",
		"fr": "Limitez InternetMaxBandwidthOut à une valeur raisonnable (par exemple, 100 Mbps).",
		"pt": "Limite InternetMaxBandwidthOut a um valor razoável (por exemplo, 100 Mbps)."
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"]
}

is_compliant(resource) if {
	bandwidth := helpers.get_property(resource, "InternetMaxBandwidthOut", 1)
	bandwidth <= 100
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetMaxBandwidthOut"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
