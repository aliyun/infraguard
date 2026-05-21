package infraguard.rules.terraform.cdn_domain_multiple_origin_servers

import rego.v1

import data.infraguard.helpers.terraform as tf

# Rule metadata
rule_meta := {
	"id": "cdn-domain-multiple-origin-servers",
	"severity": "high",
	"name": {
		"en": "CDN Domain Multiple Origin Servers",
		"zh": "CDN 域名配置多个源站",
		"ja": "CDN ドメイン複数オリジンサーバー",
		"de": "CDN-Domäne Mehrere Ursprungsserver",
		"es": "Múltiples Servidores de Origen de Dominio CDN",
		"fr": "Plusieurs Serveurs d'Origine de Domaine CDN",
		"pt": "Múltiplos Servidores de Origem do Domínio CDN"
	},
	"description": {
		"en": "CDN domains should be configured with multiple origin servers for high availability and fault tolerance.",
		"zh": "CDN 域名配置多个源站，视为合规。",
		"ja": "CDN ドメインは高可用性とフォールトトレランスのために複数のオリジンサーバーで設定する必要があります。",
		"de": "CDN-Domänen sollten mit mehreren Ursprungsservern für Hochverfügbarkeit und Fehlertoleranz konfiguriert werden.",
		"es": "Los dominios CDN deben configurarse con múltiples servidores de origen para alta disponibilidad y tolerancia a fallos.",
		"fr": "Les domaines CDN doivent être configurés avec plusieurs serveurs d'origine pour une haute disponibilité et une tolérance aux pannes.",
		"pt": "Os domínios CDN devem ser configurados com múltiplos servidores de origem para alta disponibilidade e tolerância a falhas."
	},
	"reason": {
		"en": "The CDN domain is configured with only one origin server, creating a single point of failure.",
		"zh": "CDN 域名仅配置了一个源站，存在单点故障风险。",
		"ja": "CDN ドメインが 1 つのオリジンサーバーのみで設定されているため、単一障害点が作成されます。",
		"de": "Die CDN-Domäne ist nur mit einem Ursprungsserver konfiguriert, was einen Single Point of Failure schafft.",
		"es": "El dominio CDN está configurado con solo un servidor de origen, creando un punto único de falla.",
		"fr": "Le domaine CDN est configuré avec un seul serveur d'origine, créant un point de défaillance unique.",
		"pt": "O domínio CDN está configurado com apenas um servidor de origem, criando um ponto único de falha."
	},
	"recommendation": {
		"en": "Configure at least two origin servers in the sources blocks to ensure high availability.",
		"zh": "在 sources 块中配置至少两个源站，以确保高可用性。",
		"ja": "高可用性を確保するために、sources ブロックに少なくとも 2 つのオリジンサーバーを設定します。",
		"de": "Konfigurieren Sie mindestens zwei Ursprungsserver in den sources-Blöcken, um Hochverfügbarkeit sicherzustellen.",
		"es": "Configure al menos dos servidores de origen en los bloques sources para garantizar alta disponibilidad.",
		"fr": "Configurez au moins deux serveurs d'origine dans les blocs sources pour assurer une haute disponibilité.",
		"pt": "Configure pelo menos dois servidores de origem nos blocos sources para garantir alta disponibilidade."
	},
	"resource_types": ["alicloud_cdn_domain_new"],
	"iac_type": "terraform"
}

as_array(value) := value if is_array(value)

else := [value] if is_object(value)

else := []

has_multiple_origin_servers(resource) if {
	sources := as_array(tf.get_attribute(resource, "sources", []))
	count(sources) >= 2
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_cdn_domain_new")
	not has_multiple_origin_servers(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_cdn_domain_new.%s", [name]),
		"violation_path": ["sources"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
