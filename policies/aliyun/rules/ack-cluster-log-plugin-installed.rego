package infraguard.rules.aliyun.ack_cluster_log_plugin_installed

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ack-cluster-log-plugin-installed",
	"severity": "medium",
	"name": {
		"en": "ACK Cluster Log Plugin Installed",
		"zh": "ACK 集群安装日志插件",
		"ja": "ACK クラスタログプラグインがインストールされている",
		"de": "ACK-Cluster Log-Plugin installiert",
		"es": "Complemento de Registro de Clúster ACK Instalado",
		"fr": "Plugin de Journal du Cluster ACK Installé",
		"pt": "Plugin de Log do Cluster ACK Instalado"
	},
	"description": {
		"en": "Ensures the log-service addon is installed in the ACK cluster.",
		"zh": "确保 ACK 集群中安装了 log-service 组件。",
		"ja": "ACK クラスタに log-service アドオンがインストールされていることを確認します。",
		"de": "Stellt sicher, dass das log-service-Addon im ACK-Cluster installiert ist.",
		"es": "Garantiza que el complemento log-service esté instalado en el clúster ACK.",
		"fr": "Garantit que le module complémentaire log-service est installé dans le cluster ACK.",
		"pt": "Garante que o complemento log-service esteja instalado no cluster ACK."
	},
	"reason": {
		"en": "Log collection is essential for monitoring and troubleshooting containerized applications.",
		"zh": "日志采集对于监控和排查容器化应用的故障至关重要。",
		"ja": "ログ収集は、コンテナ化アプリケーションの監視とトラブルシューティングに不可欠です。",
		"de": "Die Protokollsammlung ist für die Überwachung und Fehlerbehebung containerisierter Anwendungen unerlässlich.",
		"es": "La recopilación de registros es esencial para monitorear y solucionar problemas de aplicaciones containerizadas.",
		"fr": "La collecte de journaux est essentielle pour surveiller et dépanner les applications containerisées.",
		"pt": "A coleta de logs é essencial para monitorar e solucionar problemas de aplicações containerizadas."
	},
	"recommendation": {
		"en": "Install the 'log-service' addon in the ACK cluster settings.",
		"zh": "在 ACK 集群设置中安装 'log-service' 组件。",
		"ja": "ACK クラスタ設定で 'log-service' アドオンをインストールします。",
		"de": "Installieren Sie das 'log-service'-Addon in den ACK-Cluster-Einstellungen.",
		"es": "Instale el complemento 'log-service' en la configuración del clúster ACK.",
		"fr": "Installez le module complémentaire 'log-service' dans les paramètres du cluster ACK.",
		"pt": "Instale o complemento 'log-service' nas configurações do cluster ACK."
	},
	"resource_types": ["ALIYUN::CS::ManagedKubernetesCluster"]
}

is_compliant(resource) if {
	addons := helpers.get_property(resource, "Addons", [])
	some addon in addons
	addon.Name == "log-service"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CS::ManagedKubernetesCluster")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Addons"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
