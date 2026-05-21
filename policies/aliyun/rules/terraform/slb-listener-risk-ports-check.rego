package infraguard.rules.terraform.slb_listener_risk_ports_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "slb-listener-risk-ports-check",
	"severity": "high",
	"name": {
		"en": "SLB Listener Risk Ports Check",
		"zh": "SLB 监听禁用高风险端口",
		"ja": "SLB リスナーのリスクポートチェック",
		"de": "SLB Listener Risiko-Ports-Prüfung",
		"es": "Verificación de Puertos de Riesgo del Listener SLB",
		"fr": "Vérification des Ports à Risque du Listener SLB",
		"pt": "Verificação de Portas de Risco do Listener SLB"
	},
	"description": {
		"en": "Ensures SLB listeners do not expose high-risk ports like 22 or 3389.",
		"zh": "确保 SLB 监听未暴露 22、3389 等高风险端口。",
		"ja": "SLB リスナーが 22 や 3389 などのリスクポートを公開していないことを確認します。",
		"de": "Stellt sicher, dass SLB-Listener keine Hochrisiko-Ports wie 22 oder 3389 freigeben.",
		"es": "Garantiza que los listeners SLB no expongan puertos de alto riesgo como 22 o 3389.",
		"fr": "Garantit que les listeners SLB n'exposent pas de ports à haut risque comme 22 ou 3389.",
		"pt": "Garante que os listeners SLB não exponham portas de alto risco como 22 ou 3389."
	},
	"reason": {
		"en": "Exposing management ports to the internet via SLB increases the risk of unauthorized access.",
		"zh": "通过 SLB 向互联网暴露管理端口会增加未经授权访问的风险。",
		"ja": "SLB を介して管理ポートをインターネットに公開すると、不正アクセスのリスクが増加します。",
		"de": "Das Freigeben von Verwaltungsports über SLB an das Internet erhöht das Risiko unbefugten Zugriffs.",
		"es": "Exponer puertos de administración a internet a través de SLB aumenta el riesgo de acceso no autorizado.",
		"fr": "Exposer les ports de gestion à Internet via SLB augmente le risque d'accès non autorisé.",
		"pt": "Expor portas de gerenciamento à internet via SLB aumenta o risco de acesso não autorizado."
	},
	"recommendation": {
		"en": "Change frontend_port to a non-risky port, or use a VPN/Bastion Host for management access.",
		"zh": "将 frontend_port 更改为非高风险端口，或使用 VPN/堡垒机进行管理访问。",
		"ja": "frontend_port を非リスクポートに変更するか、管理アクセスには VPN/バスティオンホストを使用します。",
		"de": "Ändern Sie frontend_port auf einen nicht riskanten Port oder verwenden Sie ein VPN/Bastion Host für den Verwaltungszugriff.",
		"es": "Cambie frontend_port a un puerto no riesgoso, o use un VPN/Host Bastión para acceso de administración.",
		"fr": "Changez frontend_port vers un port non risqué, ou utilisez un VPN/Hôte Bastion pour l'accès de gestion.",
		"pt": "Altere frontend_port para uma porta não arriscada, ou use VPN/Host Bastião para acesso de gerenciamento."
	},
	"resource_types": ["alicloud_slb_listener"],
	"iac_type": "terraform"
}

risky_ports := {22, 3389, 3306, 6379}

is_compliant(resource) if {
	port := tf.get_attribute(resource, "frontend_port", 0)
	not tf.is_unknown(port)
	not port in risky_ports
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_slb_listener")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_slb_listener.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
