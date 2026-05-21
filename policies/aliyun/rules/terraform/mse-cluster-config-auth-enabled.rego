package infraguard.rules.terraform.mse_cluster_config_auth_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mse-cluster-config-auth-enabled",
	"severity": "medium",
	"name": {
		"en": "MSE Cluster Config Auth Enabled",
		"zh": "MSE 集群配置中心开启鉴权",
		"ja": "MSE クラスタ設定認証が有効",
		"de": "MSE-Cluster Config Auth aktiviert",
		"es": "Autenticación de Configuración de Clúster MSE Habilitada",
		"fr": "Authentification de Configuration de Cluster MSE Activée",
		"pt": "Autenticação de Configuração de Cluster MSE Habilitada"
	},
	"description": {
		"en": "MSE cluster should have ACL entry list configured for authentication and access control.",
		"zh": "MSE 集群应配置 ACL 条目列表以实现鉴权和访问控制。",
		"ja": "マイクロサービスエンジン（MSE）クラスタ設定センターで認証が有効になっていることを確認します。",
		"de": "Stellt sicher, dass das Konfigurationszentrum des Microservices Engine (MSE)-Clusters Authentifizierung aktiviert hat.",
		"es": "Garantiza que el centro de configuración del clúster del Motor de Microservicios (MSE) tenga autenticación habilitada.",
		"fr": "Garantit que le centre de configuration du cluster du moteur de microservices (MSE) a l'authentification activée.",
		"pt": "Garante que o centro de configuração do cluster do Motor de Microserviços (MSE) tenha autenticação habilitada."
	},
	"reason": {
		"en": "The MSE cluster does not have ACL entry list configured.",
		"zh": "MSE 集群未配置 ACL 条目列表。",
		"ja": "認証を有効にすることで、サービス設定への不正アクセスを防ぎます。",
		"de": "Die Aktivierung der Authentifizierung verhindert unbefugten Zugriff auf Dienstkonfigurationen.",
		"es": "Habilitar la autenticación previene el acceso no autorizado a las configuraciones del servicio.",
		"fr": "L'activation de l'authentification empêche l'accès non autorisé aux configurations de service.",
		"pt": "Habilitar a autenticação impede o acesso não autorizado às configurações do serviço."
	},
	"recommendation": {
		"en": "Configure acl_entry_list for the MSE cluster to enable authentication.",
		"zh": "为 MSE 集群配置 acl_entry_list 以启用鉴权。",
		"ja": "MSE クラスタ設定センターの認証を有効にします。",
		"de": "Aktivieren Sie die Authentifizierung für das MSE-Cluster-Konfigurationszentrum.",
		"es": "Habilite la autenticación para el centro de configuración del clúster MSE.",
		"fr": "Activez l'authentification pour le centre de configuration du cluster MSE.",
		"pt": "Habilite a autenticação para o centro de configuração do cluster MSE."
	},
	"resource_types": ["alicloud_mse_cluster"],
	"iac_type": "terraform"
}

has_acl(resource) if {
	acl_entry_list := tf.get_attribute(resource, "acl_entry_list", [])
	not tf.is_unknown(acl_entry_list)
	count(acl_entry_list) > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_cluster")
	not has_acl(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
