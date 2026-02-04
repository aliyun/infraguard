package infraguard.rules.aliyun.slb_all_listener_enabled_acl

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "slb-all-listener-enabled-acl",
	"name": {
		"en": "SLB All Listeners Have Access Control",
		"zh": "SLB 实例所有运行中的监听都设置访问控制",
		"ja": "SLB すべてのリスナーにアクセス制御がある",
		"de": "SLB Alle Listener haben Zugriffskontrolle",
		"es": "Todos los Oyentes SLB Tienen Control de Acceso",
		"fr": "Tous les Écouteurs SLB ont un Contrôle d'Accès",
		"pt": "Todos os Ouvintes SLB Têm Controle de Acesso",
	},
	"severity": "medium",
	"description": {
		"en": "All running listeners of SLB instances should have access control lists (ACL) configured for security.",
		"zh": "SLB 实例所有运行中的监听都设置了访问控制，视为合规。",
		"ja": "SLB インスタンスのすべての実行中のリスナーは、セキュリティのためにアクセス制御リスト（ACL）を設定する必要があります。",
		"de": "Alle laufenden Listener von SLB-Instanzen sollten Zugriffssteuerungslisten (ACL) für die Sicherheit konfiguriert haben.",
		"es": "Todos los oyentes en ejecución de las instancias SLB deben tener listas de control de acceso (ACL) configuradas para seguridad.",
		"fr": "Tous les écouteurs en cours d'exécution des instances SLB doivent avoir des listes de contrôle d'accès (ACL) configurées pour la sécurité.",
		"pt": "Todos os ouvintes em execução das instâncias SLB devem ter listas de controle de acesso (ACL) configuradas para segurança.",
	},
	"reason": {
		"en": "Listeners without ACL may allow unrestricted access, increasing security risks.",
		"zh": "未设置访问控制的监听可能允许无限制的访问，增加安全风险。",
		"ja": "ACL のないリスナーは無制限のアクセスを許可する可能性があり、セキュリティリスクを増加させます。",
		"de": "Listener ohne ACL können uneingeschränkten Zugriff ermöglichen, was die Sicherheitsrisiken erhöht.",
		"es": "Los oyentes sin ACL pueden permitir acceso sin restricciones, aumentando los riesgos de seguridad.",
		"fr": "Les écouteurs sans ACL peuvent autoriser un accès sans restriction, augmentant les risques de sécurité.",
		"pt": "Ouvintes sem ACL podem permitir acesso irrestrito, aumentando os riscos de segurança.",
	},
	"recommendation": {
		"en": "Configure ACL for all running listeners on SLB instances.",
		"zh": "为 SLB 实例的所有运行中监听配置访问控制列表。",
		"ja": "SLB インスタンスのすべての実行中のリスナーに ACL を設定します。",
		"de": "Konfigurieren Sie ACL für alle laufenden Listener auf SLB-Instanzen.",
		"es": "Configure ACL para todos los oyentes en ejecución en las instancias SLB.",
		"fr": "Configurez ACL pour tous les écouteurs en cours d'exécution sur les instances SLB.",
		"pt": "Configure ACL para todos os ouvintes em execução nas instâncias SLB.",
	},
	"resource_types": ["ALIYUN::SLB::Listener"],
}

is_compliant(resource) if {
	acl_status := helpers.get_property(resource, "AclStatus", "off")
	acl_status == "on"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::SLB::Listener")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AclStatus"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
