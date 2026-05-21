package infraguard.rules.terraform.slb_all_listener_enabled_acl

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-all-listener-enabled-acl",
	"severity": "medium",
	"name": {
		"en": "SLB All Listeners Have Access Control",
		"zh": "SLB 实例所有运行中的监听都设置访问控制",
		"ja": "SLB すべてのリスナーにアクセス制御がある",
		"de": "SLB Alle Listener haben Zugriffskontrolle",
		"es": "Todos los Oyentes SLB Tienen Control de Acceso",
		"fr": "Tous les Écouteurs SLB ont un Contrôle d'Accès",
		"pt": "Todos os Ouvintes SLB Têm Controle de Acesso"
	},
	"description": {
		"en": "All running listeners of SLB instances should have access control lists (ACL) configured for security.",
		"zh": "SLB 实例所有运行中的监听都设置了访问控制，视为合规。",
		"ja": "SLB インスタンスのすべての実行中のリスナーは、セキュリティのためにアクセス制御リスト（ACL）を設定する必要があります。",
		"de": "Alle laufenden Listener von SLB-Instanzen sollten Zugriffssteuerungslisten (ACL) für die Sicherheit konfiguriert haben.",
		"es": "Todos los oyentes en ejecución de las instancias SLB deben tener listas de control de acceso (ACL) configuradas para seguridad.",
		"fr": "Tous les écouteurs en cours d'exécution des instances SLB doivent avoir des listes de contrôle d'accès (ACL) configurées pour la sécurité.",
		"pt": "Todos os ouvintes em execução das instâncias SLB devem ter listas de controle de acesso (ACL) configuradas para segurança."
	},
	"reason": {
		"en": "Listeners without ACL may allow unrestricted access, increasing security risks.",
		"zh": "未设置访问控制的监听可能允许无限制的访问，增加安全风险。",
		"ja": "ACL のないリスナーは無制限のアクセスを許可する可能性があり、セキュリティリスクを増加させます。",
		"de": "Listener ohne ACL können uneingeschränkten Zugriff ermöglichen, was die Sicherheitsrisiken erhöht.",
		"es": "Los oyentes sin ACL pueden permitir acceso sin restricciones, aumentando los riesgos de seguridad.",
		"fr": "Les écouteurs sans ACL peuvent autoriser un accès sans restriction, augmentant les risques de sécurité.",
		"pt": "Ouvintes sem ACL podem permitir acesso irrestrito, aumentando os riscos de segurança."
	},
	"recommendation": {
		"en": "Set acl_status to 'on' for all SLB listeners.",
		"zh": "为所有 SLB 监听将 acl_status 设置为 'on'。",
		"ja": "すべての SLB リスナーの acl_status を 'on' に設定します。",
		"de": "Setzen Sie acl_status für alle SLB-Listener auf 'on'.",
		"es": "Establezca acl_status en 'on' para todos los oyentes SLB.",
		"fr": "Définissez acl_status sur 'on' pour tous les écouteurs SLB.",
		"pt": "Defina acl_status como 'on' para todos os ouvintes SLB."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

is_acl_enabled(resource) if {
	tf.get_attribute(resource, "acl_status", "off") == "on"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_listener")
	not is_acl_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_listener.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
