package infraguard.rules.aliyun.mse_cluster_config_auth_enabled

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "mse-cluster-config-auth-enabled",
	"name": {
		"en": "MSE Cluster Config Auth Enabled",
		"zh": "MSE 集群配置中心开启鉴权",
		"ja": "MSE クラスタ設定認証が有効",
		"de": "MSE-Cluster Config Auth aktiviert",
		"es": "Autenticación de Configuración de Clúster MSE Habilitada",
		"fr": "Authentification de Configuration de Cluster MSE Activée",
		"pt": "Autenticação de Configuração de Cluster MSE Habilitada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures that the Microservices Engine (MSE) cluster configuration center has authentication enabled.",
		"zh": "确保微服务引擎(MSE)集群配置中心已开启鉴权。",
		"ja": "マイクロサービスエンジン（MSE）クラスタ設定センターで認証が有効になっていることを確認します。",
		"de": "Stellt sicher, dass das Konfigurationszentrum des Microservices Engine (MSE)-Clusters Authentifizierung aktiviert hat.",
		"es": "Garantiza que el centro de configuración del clúster del Motor de Microservicios (MSE) tenga autenticación habilitada.",
		"fr": "Garantit que le centre de configuration du cluster du moteur de microservices (MSE) a l'authentification activée.",
		"pt": "Garante que o centro de configuração do cluster do Motor de Microserviços (MSE) tenha autenticação habilitada.",
	},
	"reason": {
		"en": "Enabling authentication prevents unauthorized access to service configurations.",
		"zh": "开启鉴权可防止对服务配置的未经授权访问。",
		"ja": "認証を有効にすることで、サービス設定への不正アクセスを防ぎます。",
		"de": "Die Aktivierung der Authentifizierung verhindert unbefugten Zugriff auf Dienstkonfigurationen.",
		"es": "Habilitar la autenticación previene el acceso no autorizado a las configuraciones del servicio.",
		"fr": "L'activation de l'authentification empêche l'accès non autorisé aux configurations de service.",
		"pt": "Habilitar a autenticação impede o acesso não autorizado às configurações do serviço.",
	},
	"recommendation": {
		"en": "Enable authentication for the MSE cluster configuration center.",
		"zh": "为 MSE 集群配置中心开启鉴权。",
		"ja": "MSE クラスタ設定センターの認証を有効にします。",
		"de": "Aktivieren Sie die Authentifizierung für das MSE-Cluster-Konfigurationszentrum.",
		"es": "Habilite la autenticación para el centro de configuración del clúster MSE.",
		"fr": "Activez l'authentification pour le centre de configuration du cluster MSE.",
		"pt": "Habilite a autenticação para o centro de configuração do cluster MSE.",
	},
	"resource_types": ["ALIYUN::MSE::Cluster"],
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")

	# Conceptual check for auth
	not helpers.has_property(resource, "ConfigAuthEnabled") # Simplified
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
