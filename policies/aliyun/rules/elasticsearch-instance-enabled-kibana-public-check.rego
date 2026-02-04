package infraguard.rules.aliyun.elasticsearch_instance_enabled_kibana_public_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-enabled-kibana-public-check",
	"name": {
		"en": "Elasticsearch Instance Kibana Does Not Enable Public Access",
		"zh": "Elasticsearch 实例 Kibana 未开启公网访问",
		"ja": "Elasticsearch インスタンス Kibana がパブリックアクセスを有効にしていない",
		"de": "Elasticsearch-Instanz Kibana aktiviert keinen öffentlichen Zugriff",
		"es": "La Instancia de Elasticsearch Kibana No Habilita el Acceso Público",
		"fr": "L'Instance Elasticsearch Kibana N'Active Pas l'Accès Public",
		"pt": "A Instância do Elasticsearch Kibana Não Habilita o Acesso Público"
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instance Kibana is not accessible from public networks.",
		"zh": "Elasticsearch 实例 Kibana 未开启公网访问，视为合规。",
		"ja": "Elasticsearch インスタンス Kibana がパブリックネットワークからアクセスできないことを確認します。",
		"de": "Stellt sicher, dass Elasticsearch-Instanz Kibana nicht von öffentlichen Netzwerken aus zugänglich ist.",
		"es": "Garantiza que la instancia de Elasticsearch Kibana no sea accesible desde redes públicas.",
		"fr": "Garantit que l'instance Elasticsearch Kibana n'est pas accessible depuis les réseaux publics.",
		"pt": "Garante que a instância do Elasticsearch Kibana não seja acessível a partir de redes públicas."
	},
	"reason": {
		"en": "Elasticsearch instance Kibana is accessible from public network, which is a security risk.",
		"zh": "Elasticsearch 实例 Kibana 开启公网访问，存在安全风险。",
		"ja": "Elasticsearch インスタンス Kibana がパブリックネットワークからアクセス可能で、セキュリティリスクがあります。",
		"de": "Elasticsearch-Instanz Kibana ist von öffentlichen Netzwerken aus zugänglich, was ein Sicherheitsrisiko darstellt.",
		"es": "La instancia de Elasticsearch Kibana es accesible desde la red pública, lo cual es un riesgo de seguridad.",
		"fr": "L'instance Elasticsearch Kibana est accessible depuis le réseau public, ce qui constitue un risque de sécurité.",
		"pt": "A instância do Elasticsearch Kibana é acessível a partir da rede pública, o que é um risco de segurança."
	},
	"recommendation": {
		"en": "Configure Kibana to only allow access from VPC or specific IPs.",
		"zh": "请配置 Kibana 仅允许 VPC 或特定 IP 访问。",
		"ja": "Kibana を VPC または特定の IP からのアクセスのみを許可するように設定します。",
		"de": "Konfigurieren Sie Kibana so, dass nur Zugriff von VPC oder bestimmten IPs erlaubt ist.",
		"es": "Configure Kibana para permitir acceso solo desde VPC o IPs específicos.",
		"fr": "Configurez Kibana pour n'autoriser l'accès qu'à partir du VPC ou d'IP spécifiques.",
		"pt": "Configure Kibana para permitir acesso apenas de VPC ou IPs específicos."
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

# Check if Kibana public access is enabled
is_kibana_public_access_enabled(resource) if {
	resource.Properties.KibanaPublicNetworkAccess == true
}

is_kibana_public_access_enabled(resource) if {
	count(resource.Properties.KibanaWhitelist) > 0
	"0.0.0.0/0" in resource.Properties.KibanaWhitelist
}

is_kibana_public_access_enabled(resource) if {
	count(resource.Properties.KibanaWhitelist) > 0
	"0.0.0.0" in resource.Properties.KibanaWhitelist
}

is_kibana_public_access_enabled(resource) if {
	resource.Properties.KibanaWhitelist == "0.0.0.0/0"
}

is_kibana_public_access_enabled(resource) if {
	resource.Properties.KibanaWhitelist == "0.0.0.0"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	is_kibana_public_access_enabled(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "KibanaPublicNetworkAccess"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
