package infraguard.rules.aliyun.ecs_snapshot_policy_timepoints_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-snapshot-policy-timepoints-check",
	"severity": "medium",
	"name": {
		"en": "ECS auto snapshot policy timepoints configured reasonably",
		"zh": "为自动快照策略设置合理的创建时间点",
		"ja": "ECS 自動スナップショットポリシーの時間ポイントが適切に設定されている",
		"de": "ECS-Automatische Momentaufnahme-Richtlinien-Zeitpunkte angemessen konfiguriert",
		"es": "Puntos de Tiempo de Política de Instantánea Automática ECS Configurados Razonablemente",
		"fr": "Points Temporels de Politique d'Instantané Automatique ECS Configurés Raisonnablement",
		"pt": "Pontos de Tempo da Política de Instantâneo Automático ECS Configurados Razoavelmente"
	},
	"description": {
		"en": "The snapshot creation timepoints in the auto snapshot policy are within the specified time range, considered compliant. Creating snapshots temporarily reduces block storage I/O performance, with performance differences generally within 10%, causing brief slowdowns. It is recommended to select timepoints that avoid business peak hours.",
		"zh": "自动快照策略中设置的快照创建时间点在参数指定的时间点范围内,视为合规。创建快照会暂时降低块存储 I/O 性能,一般性能差异在 10%以内,出现短暂瞬间变慢。建议您选择避开业务高峰的时间点。",
		"ja": "自動スナップショットポリシーのスナップショット作成時間ポイントが指定された時間範囲内にあり、準拠と見なされます。スナップショットの作成は一時的にブロックストレージの I/O パフォーマンスを低下させ、パフォーマンスの違いは一般的に 10% 以内で、短い瞬間的な速度低下を引き起こします。ビジネスのピーク時間を避ける時間ポイントを選択することをお勧めします。",
		"de": "Die Zeitpunkte für die Momentaufnahmeerstellung in der automatischen Momentaufnahme-Richtlinie liegen innerhalb des angegebenen Zeitbereichs und gelten als konform. Das Erstellen von Momentaufnahmen reduziert vorübergehend die Block-Speicher-I/O-Leistung, wobei die Leistungsunterschiede im Allgemeinen innerhalb von 10% liegen und kurze Verlangsamungen verursachen. Es wird empfohlen, Zeitpunkte zu wählen, die Geschäftsspitzenzeiten vermeiden.",
		"es": "Los puntos de tiempo de creación de instantáneas en la política de instantáneas automáticas están dentro del rango de tiempo especificado, considerado conforme. Crear instantáneas reduce temporalmente el rendimiento de E/S del almacenamiento en bloque, con diferencias de rendimiento generalmente dentro del 10%, causando ralentizaciones breves. Se recomienda seleccionar puntos de tiempo que eviten las horas pico comerciales.",
		"fr": "Les points temporels de création d'instantanés dans la politique d'instantanés automatiques sont dans la plage de temps spécifiée, considérés comme conformes. La création d'instantanés réduit temporairement les performances d'E/S du stockage en bloc, avec des différences de performance généralement inférieures à 10%, provoquant de brefs ralentissements. Il est recommandé de sélectionner des points temporels qui évitent les heures de pointe commerciales.",
		"pt": "Os pontos de tempo de criação de instantâneos na política de instantâneos automáticos estão dentro do intervalo de tempo especificado, considerado conforme. Criar instantâneos reduz temporariamente o desempenho de E/S do armazenamento em bloco, com diferenças de desempenho geralmente dentro de 10%, causando lentidões breves. Recomenda-se selecionar pontos de tempo que evitem horários de pico de negócios."
	},
	"reason": {
		"en": "Auto snapshot policy timepoints may not be configured to avoid business peak hours",
		"zh": "自动快照策略时间点可能未配置为避开业务高峰时段",
		"ja": "自動スナップショットポリシーの時間ポイントがビジネスのピーク時間を避けるように設定されていない可能性があります",
		"de": "Automatische Momentaufnahme-Richtlinien-Zeitpunkte sind möglicherweise nicht so konfiguriert, dass Geschäftsspitzenzeiten vermieden werden",
		"es": "Los puntos de tiempo de la política de instantáneas automáticas pueden no estar configurados para evitar las horas pico comerciales",
		"fr": "Les points temporels de la politique d'instantanés automatiques peuvent ne pas être configurés pour éviter les heures de pointe commerciales",
		"pt": "Os pontos de tempo da política de instantâneos automáticos podem não estar configurados para evitar horários de pico de negócios"
	},
	"recommendation": {
		"en": "Configure snapshot creation timepoints during off-peak hours (e.g., 2:00-6:00 AM) to minimize impact on business operations",
		"zh": "将快照创建时间点配置在非高峰时段(如凌晨 2:00-6:00)以最小化对业务运营的影响",
		"ja": "業務運営への影響を最小限に抑えるために、オフピーク時間（例：午前 2:00-6:00）にスナップショット作成時間ポイントを設定します",
		"de": "Konfigurieren Sie Zeitpunkte für die Momentaufnahmeerstellung während der Nebenzeiten (z. B. 2:00-6:00 Uhr), um die Auswirkungen auf Geschäftsbetriebe zu minimieren",
		"es": "Configure puntos de tiempo de creación de instantáneas durante horas de menor actividad (por ejemplo, 2:00-6:00 AM) para minimizar el impacto en las operaciones comerciales",
		"fr": "Configurez les points temporels de création d'instantanés pendant les heures creuses (par exemple, 2h00-6h00) pour minimiser l'impact sur les opérations commerciales",
		"pt": "Configure pontos de tempo de criação de instantâneos durante horários de menor movimento (por exemplo, 2:00-6:00) para minimizar o impacto nas operações comerciais"
	},
	"resource_types": ["ALIYUN::ECS::AutoSnapshotPolicy"]
}

# Recommended off-peak hours: 2:00-6:00 AM (hours 2-5)
recommended_timepoints := {2, 3, 4, 5}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::AutoSnapshotPolicy")

	# Get configured timepoints
	timepoints := helpers.get_property(resource, "TimePoints", [])

	# Check if any timepoint is outside recommended range
	some point in timepoints
	not point in recommended_timepoints

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TimePoints"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
