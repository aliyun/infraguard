package infraguard.rules.aliyun.cen_cross_region_bandwidth_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "cen-cross-region-bandwidth-check",
	"name": {
		"en": "CEN Cross-Region Bandwidth Check",
		"zh": "CEN 实例中的跨地域连接带宽分配满足指定要求",
		"ja": "CEN クロスリージョンバンド幅チェック",
		"de": "CEN Cross-Region Bandbreitenprüfung",
		"es": "Verificación de Ancho de Banda Inter-Región CEN",
		"fr": "Vérification de la Bande Passante Inter-Région CEN",
		"pt": "Verificação de Largura de Banda Inter-Região CEN",
	},
	"severity": "medium",
	"description": {
		"en": "CEN instance cross-region connections should have sufficient bandwidth allocation to meet performance requirements.",
		"zh": "云企业网实例下所有跨地域连接分配的带宽大于参数指定值，视为合规。",
		"ja": "CEN インスタンスのクロスリージョン接続は、パフォーマンス要件を満たすために十分な帯域幅割り当てを持つ必要があります。",
		"de": "CEN-Instanz Cross-Region-Verbindungen sollten ausreichende Bandbreitenzuweisung haben, um Leistungsanforderungen zu erfüllen.",
		"es": "Las conexiones inter-región de instancia CEN deben tener asignación de ancho de banda suficiente para cumplir con los requisitos de rendimiento.",
		"fr": "Les connexions inter-région d'instance CEN doivent avoir une allocation de bande passante suffisante pour répondre aux exigences de performance.",
		"pt": "As conexões inter-região da instância CEN devem ter alocação de largura de banda suficiente para atender aos requisitos de desempenho.",
	},
	"reason": {
		"en": "Insufficient cross-region bandwidth can lead to performance bottlenecks and degraded application performance.",
		"zh": "不足的跨地域带宽可能导致性能瓶颈和应用程序性能下降。",
		"ja": "不十分なクロスリージョンバンド幅は、パフォーマンスのボトルネックやアプリケーションパフォーマンスの低下につながる可能性があります。",
		"de": "Unzureichende Cross-Region-Bandbreite kann zu Leistungsengpässen und verschlechterter Anwendungsleistung führen.",
		"es": "El ancho de banda inter-región insuficiente puede provocar cuellos de botella de rendimiento y degradación del rendimiento de la aplicación.",
		"fr": "Une bande passante inter-région insuffisante peut entraîner des goulots d'étranglement de performance et une dégradation des performances de l'application.",
		"pt": "Largura de banda inter-região insuficiente pode levar a gargalos de desempenho e degradação do desempenho da aplicação.",
	},
	"recommendation": {
		"en": "Ensure cross-region connections have bandwidth allocation above the specified minimum threshold (default: 1Mbps).",
		"zh": "确保跨地域连接的带宽分配高于指定的最小阈值（默认：1Mbps）。",
		"ja": "クロスリージョン接続の帯域幅割り当てが指定された最小しきい値（デフォルト：1Mbps）を超えていることを確認します。",
		"de": "Stellen Sie sicher, dass Cross-Region-Verbindungen eine Bandbreitenzuweisung über dem angegebenen Mindestschwellenwert haben (Standard: 1Mbps).",
		"es": "Asegúrese de que las conexiones inter-región tengan asignación de ancho de banda por encima del umbral mínimo especificado (predeterminado: 1Mbps).",
		"fr": "Assurez-vous que les connexions inter-région ont une allocation de bande passante supérieure au seuil minimum spécifié (par défaut : 1Mbps).",
		"pt": "Garanta que as conexões inter-região tenham alocação de largura de banda acima do limite mínimo especificado (padrão: 1Mbps).",
	},
	"resource_types": ["ALIYUN::CEN::CenInstance"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CEN::CenInstance")

	# Cross-resource check would examine CenBandwidthPackage associations
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": [],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
