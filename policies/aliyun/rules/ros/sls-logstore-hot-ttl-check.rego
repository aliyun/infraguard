package infraguard.rules.aliyun.sls_logstore_hot_ttl_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "sls-logstore-hot-ttl-check",
	"severity": "low",
	"name": {
		"en": "SLS Logstore Smart Tier Storage Enabled",
		"zh": "SLS 日志库开启智能冷热分层存储",
		"ja": "SLS ログストアスマートティアストレージが有効",
		"de": "SLS Logstore Smart Tier Storage aktiviert",
		"es": "Almacenamiento de Nivel Inteligente de Logstore SLS Habilitado",
		"fr": "Stockage à Niveaux Intelligents de Logstore SLS Activé",
		"pt": "Armazenamento de Camada Inteligente do Logstore SLS Habilitado"
	},
	"description": {
		"en": "Ensures SLS Logstores have intelligent hot/cold tier storage enabled for cost optimization.",
		"zh": "确保 SLS 日志库开启了智能冷热分层存储功能以优化成本。",
		"ja": "SLS ログストアでコスト最適化のためにインテリジェントなホット/コールドティアストレージが有効になっていることを確認します。",
		"de": "Stellt sicher, dass SLS-Logstores intelligentes Hot/Cold-Tier-Speicher für die Kostenoptimierung aktiviert haben.",
		"es": "Garantiza que los Logstores SLS tengan almacenamiento inteligente de nivel caliente/frío habilitado para optimización de costos.",
		"fr": "Garantit que les Logstores SLS ont le stockage intelligent à niveaux chaud/froid activé pour l'optimisation des coûts.",
		"pt": "Garante que os Logstores SLS tenham armazenamento inteligente de camada quente/fria habilitado para otimização de custos."
	},
	"reason": {
		"en": "Hot/cold tier storage helps optimize costs by automatically moving less frequently accessed data to cheaper storage.",
		"zh": "智能冷热分层存储通过将访问频率较低的数据自动移动到更便宜的存储层来帮助优化成本。",
		"ja": "ホット/コールドティアストレージは、アクセス頻度の低いデータを自動的により安価なストレージに移動することで、コストの最適化に役立ちます。",
		"de": "Hot/Cold-Tier-Speicher hilft bei der Kostenoptimierung, indem weniger häufig aufgerufene Daten automatisch in günstigeren Speicher verschoben werden.",
		"es": "El almacenamiento de nivel caliente/frío ayuda a optimizar los costos al mover automáticamente los datos menos accedidos a un almacenamiento más barato.",
		"fr": "Le stockage à niveaux chaud/froid aide à optimiser les coûts en déplaçant automatiquement les données moins fréquemment consultées vers un stockage moins cher.",
		"pt": "O armazenamento de camada quente/fria ajuda a otimizar custos movendo automaticamente dados menos acessados para armazenamento mais barato."
	},
	"recommendation": {
		"en": "Enable intelligent hot/cold tier storage for the Logstore.",
		"zh": "为日志库启用智能冷热分层存储功能。",
		"ja": "ログストアのインテリジェントなホット/コールドティアストレージを有効にします。",
		"de": "Aktivieren Sie intelligentes Hot/Cold-Tier-Speicher für den Logstore.",
		"es": "Habilite el almacenamiento inteligente de nivel caliente/frío para el Logstore.",
		"fr": "Activez le stockage intelligent à niveaux chaud/froid pour le Logstore.",
		"pt": "Habilite o armazenamento inteligente de camada quente/fria para o Logstore."
	},
	"resource_types": ["ALIYUN::SLS::Logstore"]
}

is_compliant(resource) if {
	# Check TTL - hot storage enabled when TTL > 7 days
	# Standard tier with TTL > 7 days indicates hot storage is available
	ttl := helpers.get_property(resource, "TTL", 0)
	ttl > 7

	# Check that PreserveStorage is not true (if true, TTL is ignored)
	preserve := helpers.get_property(resource, "PreserveStorage", false)
	preserve != true
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLS::Logstore")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "TTL"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
