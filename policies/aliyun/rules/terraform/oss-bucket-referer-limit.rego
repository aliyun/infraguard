package infraguard.rules.terraform.oss_bucket_referer_limit

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "oss-bucket-referer-limit",
	"severity": "low",
	"name": {
		"en": "OSS Bucket Referer Hotlink Protection",
		"zh": "OSS 存储空间 Referer 在指定的防盗链白名单中",
		"ja": "OSS バケットの Referer ホットリンク保護が設定されている",
		"de": "OSS-Bucket Referer-Hotlink-Schutz konfiguriert",
		"es": "Protección de enlace directo de referer de bucket OSS configurada",
		"fr": "Protection contre les liens directs de referer de bucket OSS configurée",
		"pt": "Proteção contra link direto de referer de bucket OSS configurada"
	},
	"description": {
		"en": "Ensures OSS bucket has referer-based hotlink protection configured.",
		"zh": "确保 OSS 存储桶配置了基于 Referer 的防盗链保护。",
		"ja": "OSS バケットで Referer ホットリンク保護が有効になり、ホワイトリストが設定されています。",
		"de": "OSS-Bucket hat Referer-Hotlink-Schutz mit konfigurierter Whitelist aktiviert.",
		"es": "El bucket OSS tiene protección contra enlaces directos de referer habilitada con una lista blanca configurada.",
		"fr": "Le bucket OSS a la protection contre les liens directs de referer activée avec une liste blanche configurée.",
		"pt": "O bucket OSS tem proteção contra link direto de referer habilitada com uma lista branca configurada."
	},
	"reason": {
		"en": "The OSS bucket does not have referer-based hotlink protection configured.",
		"zh": "OSS 存储桶未配置基于 Referer 的防盗链保护。",
		"ja": "OSS バケットに Referer ホットリンク保護が設定されていないため、不正アクセスや帯域幅の盗用につながる可能性があります。",
		"de": "OSS-Bucket hat keinen Referer-Hotlink-Schutz konfiguriert, was zu unbefugtem Zugriff und Bandbreitendiebstahl führen kann.",
		"es": "El bucket OSS no tiene protección contra enlaces directos de referer configurada, lo que puede llevar a acceso no autorizado y robo de ancho de banda.",
		"fr": "Le bucket OSS n'a pas de protection contre les liens directs de referer configurée, ce qui peut entraîner un accès non autorisé et un vol de bande passante.",
		"pt": "O bucket OSS não tem proteção contra link direto de referer configurada, o que pode levar a acesso não autorizado e roubo de largura de banda."
	},
	"recommendation": {
		"en": "Configure referer_config with a non-empty referers list for hotlink protection.",
		"zh": "配置 referer_config 并设置非空的 referers 列表以实现防盗链保护。",
		"ja": "空でない RefererList を使用して RefererConfiguration を設定することで、OSS バケットの Referer ホワイトリストを設定します。",
		"de": "Konfigurieren Sie eine Referer-Whitelist für den OSS-Bucket, indem Sie RefererConfiguration mit einer nicht leeren RefererList setzen.",
		"es": "Configure la lista blanca de referer para el bucket OSS estableciendo RefererConfiguration con una RefererList no vacía.",
		"fr": "Configurez la liste blanche de referer pour le bucket OSS en définissant RefererConfiguration avec une RefererList non vide.",
		"pt": "Configure a lista branca de referer para o bucket OSS definindo RefererConfiguration com uma RefererList não vazia."
	},
	"resource_types": ["alicloud_oss_bucket"],
	"iac_type": "terraform"
}

has_referer_config(resource) if {
	referer_config := tf.get_attribute(resource, "referer_config", {})
	referers := object.get(referer_config, "referers", [])
	is_array(referers)
	count(referers) > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_oss_bucket")
	not has_referer_config(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_oss_bucket.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
