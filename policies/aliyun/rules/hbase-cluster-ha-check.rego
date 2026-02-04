package infraguard.rules.aliyun.hbase_cluster_ha_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "hbase-cluster-ha-check",
	"name": {
		"en": "HBase Cluster HA Enabled",
		"zh": "HBase 集群强制开启高可用",
		"ja": "HBase クラスターの HA が有効",
		"de": "HBase-Cluster HA aktiviert",
		"es": "HA de Clúster HBase Habilitado",
		"fr": "HA du Cluster HBase Activé",
		"pt": "HA do Cluster HBase Habilitado"
	},
	"severity": "high",
	"description": {
		"en": "Ensures HBase clusters are configured for High Availability (HA).",
		"zh": "确保 HBase 集群配置为高可用（HA）模式。",
		"ja": "HBase クラスターが高可用性（HA）用に設定されていることを確認します。",
		"de": "Stellt sicher, dass HBase-Cluster für hohe Verfügbarkeit (HA) konfiguriert sind.",
		"es": "Garantiza que los clústeres HBase estén configurados para Alta Disponibilidad (HA).",
		"fr": "Garantit que les clusters HBase sont configurés pour la Haute Disponibilité (HA).",
		"pt": "Garante que os clusters HBase estejam configurados para Alta Disponibilidade (HA)."
	},
	"reason": {
		"en": "Non-HA clusters are single points of failure and may lead to service downtime.",
		"zh": "非高可用集群存在单点故障风险，可能导致服务中断。",
		"ja": "非 HA クラスターは単一障害点であり、サービスダウンタイムにつながる可能性があります。",
		"de": "Nicht-HA-Cluster sind Single Points of Failure und können zu Serviceausfällen führen.",
		"es": "Los clústeres no HA son puntos únicos de falla y pueden provocar tiempo de inactividad del servicio.",
		"fr": "Les clusters non-HA sont des points de défaillance unique et peuvent entraîner des temps d'arrêt du service.",
		"pt": "Clusters não-HA são pontos únicos de falha e podem levar a tempo de inatividade do serviço."
	},
	"recommendation": {
		"en": "Ensure NodeCount is sufficient for HA (at least 2 for disk-based, 3 for local disks).",
		"zh": "确保节点数量满足高可用要求（磁盘型至少 2 个，本地盘型至少 3 个）。",
		"ja": "HA に十分な NodeCount を確保します（ディスクベースの場合は少なくとも 2、ローカルディスクの場合は少なくとも 3）。",
		"de": "Stellen Sie sicher, dass NodeCount für HA ausreicht (mindestens 2 für disk-basiert, 3 für lokale Festplatten).",
		"es": "Asegúrese de que NodeCount sea suficiente para HA (al menos 2 para basado en disco, 3 para discos locales).",
		"fr": "Assurez-vous que NodeCount est suffisant pour HA (au moins 2 pour basé sur disque, 3 pour disques locaux).",
		"pt": "Garanta que NodeCount seja suficiente para HA (pelo menos 2 para baseado em disco, 3 para discos locais)."
	},
	"resource_types": ["ALIYUN::HBase::Cluster"],
}

is_compliant(resource) if {
	count := helpers.get_property(resource, "NodeCount", 1)
	count >= 2
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::HBase::Cluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "NodeCount"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
