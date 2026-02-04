package infraguard.rules.aliyun.ack_cluster_rrsa_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ack-cluster-rrsa-enabled",
	"name": {
		"en": "ACK Cluster RRSA Enabled",
		"zh": "ACK 集群开启 RRSA",
		"ja": "ACK クラスタで RRSA が有効",
		"de": "ACK-Cluster RRSA aktiviert",
		"es": "RRSA del Cluster ACK Habilitado",
		"fr": "RRSA du Cluster ACK Activé",
		"pt": "RRSA do Cluster ACK Habilitado",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the RAM Roles for Service Accounts (RRSA) feature is enabled for the ACK cluster.",
		"zh": "确保 ACK 集群开启了 RAM 角色注入(RRSA)功能。",
		"ja": "ACK クラスタで RAM Roles for Service Accounts (RRSA) 機能が有効になっていることを確認します。",
		"de": "Stellt sicher, dass die RAM Roles for Service Accounts (RRSA)-Funktion für den ACK-Cluster aktiviert ist.",
		"es": "Garantiza que la función RAM Roles for Service Accounts (RRSA) esté habilitada para el clúster ACK.",
		"fr": "Garantit que la fonctionnalité RAM Roles for Service Accounts (RRSA) est activée pour le cluster ACK.",
		"pt": "Garante que o recurso RAM Roles for Service Accounts (RRSA) está habilitado para o cluster ACK.",
	},
	"reason": {
		"en": "RRSA allows pods to assume RAM roles, providing a more secure and fine-grained way to manage permissions.",
		"zh": "RRSA 允许 Pod 扮演 RAM 角色，提供更安全、更细粒度的权限管理方式。",
		"ja": "RRSA により、Pod が RAM ロールを引き受けることができ、より安全で細かい権限管理方法を提供します。",
		"de": "RRSA ermöglicht es Pods, RAM-Rollen zu übernehmen, was eine sicherere und feinere Art der Berechtigungsverwaltung bietet.",
		"es": "RRSA permite que los pods asuman roles RAM, proporcionando una forma más segura y granular de gestionar permisos.",
		"fr": "RRSA permet aux pods d'assumer des rôles RAM, offrant une manière plus sécurisée et granulaire de gérer les permissions.",
		"pt": "O RRSA permite que pods assumam funções RAM, fornecendo uma maneira mais segura e granular de gerenciar permissões.",
	},
	"recommendation": {
		"en": "Enable RRSA for the ACK cluster.",
		"zh": "为 ACK 集群开启 RRSA 功能。",
		"ja": "ACK クラスタで RRSA を有効にします。",
		"de": "Aktivieren Sie RRSA für den ACK-Cluster.",
		"es": "Habilite RRSA para el clúster ACK.",
		"fr": "Activez RRSA pour le cluster ACK.",
		"pt": "Habilite RRSA para o cluster ACK.",
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::CS::ManagedKubernetesCluster", "ALIYUN::CS::AnyCluster"])
	rrsa_config := helpers.get_property(resource, "RrsaConfig", {})
	enabled := rrsa_config.Enabled
	not helpers.is_true(enabled)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RrsaConfig", "Enabled"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
