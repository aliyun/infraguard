package infraguard.rules.terraform.sls_logstore_hot_ttl_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Set retention_period to greater than 7 days to enable intelligent hot/cold tier storage.",
		"zh": "将 retention_period 设置为大于 7 天以启用智能冷热分层存储。",
		"ja": "インテリジェントなホット/コールドティアストレージを有効にするために retention_period を 7 日以上に設定します。",
		"de": "Setzen Sie retention_period auf mehr als 7 Tage, um intelligentes Hot/Cold-Tier-Speicher zu aktivieren.",
		"es": "Establezca retention_period en más de 7 días para habilitar almacenamiento inteligente de nivel caliente/frío.",
		"fr": "Définissez retention_period à plus de 7 jours pour activer le stockage intelligent à niveaux chaud/froid.",
		"pt": "Defina retention_period para mais de 7 dias para habilitar armazenamento inteligente de camada quente/fria."
	},
	"resource_types": ["alicloud_log_store"],
	"iac_type": "terraform"
}

has_sufficient_retention(resource) if {
	retention := tf.get_attribute(resource, "retention_period", 0)
	not tf.is_unknown(retention)
	retention > 7
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_log_store")
	not has_sufficient_retention(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_log_store.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
