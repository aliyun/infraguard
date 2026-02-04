package infraguard.rules.aliyun.ack_cluster_spec_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ack-cluster-spec-check",
	"name": {
		"en": "ACK Cluster Spec Check",
		"zh": "ACK 集群规格核查",
		"ja": "ACK クラスタ仕様チェック",
		"de": "ACK-Cluster-Spezifikationsprüfung",
		"es": "Verificación de Especificación de Clúster ACK",
		"fr": "Vérification de Spécification de Cluster ACK",
		"pt": "Verificação de Especificação de Cluster ACK",
	},
	"severity": "low",
	"description": {
		"en": "Ensures ACK clusters use approved specifications (e.g., ACK Pro).",
		"zh": "确保 ACK 集群使用批准的规格（如专业版 ACK Pro）。",
		"ja": "ACK クラスタが承認された仕様（例：ACK Pro）を使用することを確認します。",
		"de": "Stellt sicher, dass ACK-Cluster genehmigte Spezifikationen (z. B. ACK Pro) verwenden.",
		"es": "Garantiza que los clústeres ACK usen especificaciones aprobadas (por ejemplo, ACK Pro).",
		"fr": "Garantit que les clusters ACK utilisent des spécifications approuvées (par exemple, ACK Pro).",
		"pt": "Garante que os clusters ACK usem especificações aprovadas (por exemplo, ACK Pro).",
	},
	"reason": {
		"en": "ACK Pro version clusters provide better reliability and SLA guarantees for production workloads.",
		"zh": "ACK 专业版集群为生产工作负载提供更好的可靠性和 SLA 保障。",
		"ja": "ACK Pro バージョンのクラスタは、本番ワークロードに優れた信頼性と SLA 保証を提供します。",
		"de": "ACK Pro-Version-Cluster bieten bessere Zuverlässigkeit und SLA-Garantien für Produktions-Workloads.",
		"es": "Los clústeres de versión ACK Pro proporcionan mejor confiabilidad y garantías SLA para cargas de trabajo de producción.",
		"fr": "Les clusters de version ACK Pro offrent une meilleure fiabilité et des garanties SLA pour les charges de travail de production.",
		"pt": "Os clusters da versão ACK Pro fornecem melhor confiabilidade e garantias de SLA para cargas de trabalho de produção.",
	},
	"recommendation": {
		"en": "Upgrade the cluster to 'ack.pro.small' for production environments.",
		"zh": "对于生产环境，建议将集群规格升级为 'ack.pro.small'。",
		"ja": "本番環境では、クラスタを 'ack.pro.small' にアップグレードします。",
		"de": "Aktualisieren Sie den Cluster auf 'ack.pro.small' für Produktionsumgebungen.",
		"es": "Actualice el clúster a 'ack.pro.small' para entornos de producción.",
		"fr": "Mettez à niveau le cluster vers 'ack.pro.small' pour les environnements de production.",
		"pt": "Atualize o cluster para 'ack.pro.small' para ambientes de produção.",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"],
}

is_compliant(resource) if {
	spec := helpers.get_property(resource, "ClusterSpec", "")
	spec == "ack.pro.small"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "ClusterSpec"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
