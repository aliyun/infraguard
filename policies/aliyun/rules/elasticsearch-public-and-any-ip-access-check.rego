package infraguard.rules.aliyun.elasticsearch_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "elasticsearch-public-and-any-ip-access-check",
	"name": {
		"en": "Elasticsearch Public and Any IP Access Check",
		"zh": "Elasticsearch 实例未开启公网或不允许任意 IP 访问",
		"ja": "Elasticsearch パブリックおよび任意の IP アクセスチェック",
		"de": "Elasticsearch Öffentlicher und Beliebiger IP-Zugriff Prüfung",
		"es": "Verificación de Acceso Público y de Cualquier IP de Elasticsearch",
		"fr": "Vérification d'Accès Public et IP Elasticsearch",
		"pt": "Verificação de Acesso Público e de Qualquer IP do Elasticsearch",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that Elasticsearch instances do not have public access enabled or an open whitelist.",
		"zh": "确保 Elasticsearch 实例未开启公网访问，或者白名单未设置为对所有 IP 开放。",
		"ja": "Elasticsearch インスタンスでパブリックアクセスが有効になっていない、またはオープンホワイトリストが設定されていないことを確認します。",
		"de": "Stellt sicher, dass Elasticsearch-Instanzen keinen öffentlichen Zugriff aktiviert haben oder eine offene Whitelist haben.",
		"es": "Garantiza que las instancias Elasticsearch no tengan acceso público habilitado o una lista blanca abierta.",
		"fr": "Garantit que les instances Elasticsearch n'ont pas d'accès public activé ou une liste blanche ouverte.",
		"pt": "Garante que as instâncias Elasticsearch não tenham acesso público habilitado ou uma lista branca aberta.",
	},
	"reason": {
		"en": "Public access or an open whitelist exposes the Elasticsearch cluster to the internet, increasing the risk of unauthorized access or attacks.",
		"zh": "开启公网访问或设置开放白名单会将 Elasticsearch 集群暴露在互联网上，增加未经授权访问或攻击的风险。",
		"ja": "パブリックアクセスまたはオープンホワイトリストにより、Elasticsearch クラスタがインターネットに公開され、不正アクセスや攻撃のリスクが増加します。",
		"de": "Öffentlicher Zugriff oder eine offene Whitelist setzt den Elasticsearch-Cluster dem Internet aus und erhöht das Risiko unbefugten Zugriffs oder Angriffe.",
		"es": "El acceso público o una lista blanca abierta expone el clúster Elasticsearch a Internet, aumentando el riesgo de acceso no autorizado o ataques.",
		"fr": "L'accès public ou une liste blanche ouverte expose le cluster Elasticsearch à Internet, augmentant le risque d'accès non autorisé ou d'attaques.",
		"pt": "O acesso público ou uma lista branca aberta expõe o cluster Elasticsearch à Internet, aumentando o risco de acesso não autorizado ou ataques.",
	},
	"recommendation": {
		"en": "Disable public access or restrict the IP whitelist for the Elasticsearch instance.",
		"zh": "禁用 Elasticsearch 实例的公网访问或限制 IP 白名单。",
		"ja": "Elasticsearch インスタンスのパブリックアクセスを無効にするか、IP ホワイトリストを制限します。",
		"de": "Deaktivieren Sie den öffentlichen Zugriff oder beschränken Sie die IP-Whitelist für die Elasticsearch-Instanz.",
		"es": "Deshabilite el acceso público o restrinja la lista blanca de IP para la instancia Elasticsearch.",
		"fr": "Désactivez l'accès public ou restreignez la liste blanche IP pour l'instance Elasticsearch.",
		"pt": "Desabilite o acesso público ou restrinja a lista branca de IP para a instância Elasticsearch.",
	},
	"resource_types": ["ALIYUN::ElasticSearch::Instance"],
}

is_compliant(resource) if {
	# If public access is not enabled, it's compliant
	not helpers.is_true(helpers.get_property(resource, "EnablePublic", false))
}

is_compliant(resource) if {
	# If public access is enabled, check the whitelist
	helpers.is_true(helpers.get_property(resource, "EnablePublic", false))
	whitelist := helpers.get_property(resource, "PublicWhitelist", [])
	not has_open_cidr(whitelist)
}

has_open_cidr(whitelist) if {
	some cidr in whitelist
	helpers.is_public_cidr(cidr)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ElasticSearch::Instance")
	not is_compliant(resource)
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
