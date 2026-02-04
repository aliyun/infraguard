package infraguard.rules.aliyun.elasticsearch_instance_enabled_public_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "elasticsearch-instance-enabled-public-check",
	"severity": "high",
	"name": {
		"en": "Elasticsearch Instance Does Not Enable Public Access",
		"zh": "Elasticsearch 实例未开启公网访问",
		"ja": "Elasticsearch インスタンスがパブリックアクセスを有効にしていない",
		"de": "Elasticsearch-Instanz aktiviert keinen öffentlichen Zugriff",
		"es": "La Instancia Elasticsearch No Habilita Acceso Público",
		"fr": "L'Instance Elasticsearch N'active Pas l'Accès Public",
		"pt": "A Instância Elasticsearch Não Habilita Acesso Público"
	},
	"description": {
		"en": "Ensures that Elasticsearch instances are not accessible from public networks.",
		"zh": "Elasticsearch 实例未开启公网访问，视为合规。",
		"ja": "Elasticsearch インスタンスがパブリックネットワークからアクセスできないことを確認します。",
		"de": "Stellt sicher, dass Elasticsearch-Instanzen nicht von öffentlichen Netzwerken aus zugänglich sind.",
		"es": "Garantiza que las instancias Elasticsearch no sean accesibles desde redes públicas.",
		"fr": "Garantit que les instances Elasticsearch ne sont pas accessibles depuis les réseaux publics.",
		"pt": "Garante que as instâncias Elasticsearch não sejam acessíveis de redes públicas."
	},
	"reason": {
		"en": "Elasticsearch instance is accessible from public network, which is a security risk.",
		"zh": "Elasticsearch 实例开启公网访问，存在安全风险。",
		"ja": "Elasticsearch インスタンスがパブリックネットワークからアクセス可能であり、セキュリティリスクがあります。",
		"de": "Elasticsearch-Instanz ist von öffentlichen Netzwerken aus zugänglich, was ein Sicherheitsrisiko darstellt.",
		"es": "La instancia Elasticsearch es accesible desde la red pública, lo que es un riesgo de seguridad.",
		"fr": "L'instance Elasticsearch est accessible depuis le réseau public, ce qui constitue un risque de sécurité.",
		"pt": "A instância Elasticsearch é acessível de redes públicas, o que é um risco de segurança."
	},
	"recommendation": {
		"en": "Configure the instance to only allow access from VPC or specific IPs.",
		"zh": "请配置实例仅允许 VPC 或特定 IP 访问。",
		"ja": "インスタンスを VPC または特定の IP からのアクセスのみを許可するように設定します。",
		"de": "Konfigurieren Sie die Instanz so, dass nur Zugriff von VPC oder bestimmten IPs erlaubt ist.",
		"es": "Configure la instancia para permitir acceso solo desde VPC o IPs específicas.",
		"fr": "Configurez l'instance pour n'autoriser l'accès que depuis VPC ou des IP spécifiques.",
		"pt": "Configure a instância para permitir acesso apenas de VPC ou IPs específicos."
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"]
}

# Check if public network access is enabled
is_public_access_enabled(resource) if {
	resource.Properties.EnablePublic == true
}

is_public_access_enabled(resource) if {
	count(resource.Properties.PublicWhitelist) > 0
	"0.0.0.0/0" in resource.Properties.PublicWhitelist
}

is_public_access_enabled(resource) if {
	count(resource.Properties.PublicWhitelist) > 0
	"0.0.0.0" in resource.Properties.PublicWhitelist
}

is_public_access_enabled(resource) if {
	resource.Properties.PublicWhitelist == "0.0.0.0/0"
}

is_public_access_enabled(resource) if {
	resource.Properties.PublicWhitelist == "0.0.0.0"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	is_public_access_enabled(resource)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "EnablePublic"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
