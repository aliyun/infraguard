package infraguard.rules.aliyun.oss_bucket_referer_limit

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "oss-bucket-referer-limit",
	"name": {
		"en": "OSS bucket referer hotlink protection configured",
		"zh": "OSS 存储空间 Referer 在指定的防盗链白名单中",
		"ja": "OSS バケットの Referer ホットリンク保護が設定されている",
		"de": "OSS-Bucket Referer-Hotlink-Schutz konfiguriert",
		"es": "Protección de enlace directo de referer de bucket OSS configurada",
		"fr": "Protection contre les liens directs de referer de bucket OSS configurée",
		"pt": "Proteção contra link direto de referer de bucket OSS configurada",
	},
	"description": {
		"en": "OSS bucket has referer hotlink protection enabled with a configured whitelist.",
		"zh": "OSS 存储空间开启防盗链并且 Referer 在指定白名单中。",
		"ja": "OSS バケットで Referer ホットリンク保護が有効になり、ホワイトリストが設定されています。",
		"de": "OSS-Bucket hat Referer-Hotlink-Schutz mit konfigurierter Whitelist aktiviert.",
		"es": "El bucket OSS tiene protección contra enlaces directos de referer habilitada con una lista blanca configurada.",
		"fr": "Le bucket OSS a la protection contre les liens directs de referer activée avec une liste blanche configurée.",
		"pt": "O bucket OSS tem proteção contra link direto de referer habilitada com uma lista branca configurada.",
	},
	"severity": "low",
	"resource_types": ["ALIYUN::OSS::Bucket"],
	"reason": {
		"en": "OSS bucket does not have referer hotlink protection configured, which may lead to unauthorized access and bandwidth theft.",
		"zh": "OSS 存储空间未配置 Referer 防盗链,可能导致未授权访问和流量盗用。",
		"ja": "OSS バケットに Referer ホットリンク保護が設定されていないため、不正アクセスや帯域幅の盗用につながる可能性があります。",
		"de": "OSS-Bucket hat keinen Referer-Hotlink-Schutz konfiguriert, was zu unbefugtem Zugriff und Bandbreitendiebstahl führen kann.",
		"es": "El bucket OSS no tiene protección contra enlaces directos de referer configurada, lo que puede llevar a acceso no autorizado y robo de ancho de banda.",
		"fr": "Le bucket OSS n'a pas de protection contre les liens directs de referer configurée, ce qui peut entraîner un accès non autorisé et un vol de bande passante.",
		"pt": "O bucket OSS não tem proteção contra link direto de referer configurada, o que pode levar a acesso não autorizado e roubo de largura de banda.",
	},
	"recommendation": {
		"en": "Configure referer whitelist for OSS bucket by setting RefererConfiguration with a non-empty RefererList.",
		"zh": "通过设置 RefererConfiguration 并配置非空的 RefererList 为 OSS 存储空间配置 Referer 白名单。",
		"ja": "空でない RefererList を使用して RefererConfiguration を設定することで、OSS バケットの Referer ホワイトリストを設定します。",
		"de": "Konfigurieren Sie eine Referer-Whitelist für den OSS-Bucket, indem Sie RefererConfiguration mit einer nicht leeren RefererList setzen.",
		"es": "Configure la lista blanca de referer para el bucket OSS estableciendo RefererConfiguration con una RefererList no vacía.",
		"fr": "Configurez la liste blanche de referer pour le bucket OSS en définissant RefererConfiguration avec une RefererList non vide.",
		"pt": "Configure a lista branca de referer para o bucket OSS definindo RefererConfiguration com uma RefererList não vazia.",
	},
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")

	# Check if referer configuration exists and has a non-empty list
	referer_config := helpers.get_property(resource, "RefererConfiguration", {})
	referer_list := object.get(referer_config, "RefererList", [])

	# Compliant if referer list is configured and not empty
	count(referer_list) == 0

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RefererConfiguration"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
