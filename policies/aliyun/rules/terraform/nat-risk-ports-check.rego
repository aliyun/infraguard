package infraguard.rules.terraform.nat_risk_ports_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "nat-risk-ports-check",
	"severity": "high",
	"name": {
		"en": "NAT Gateway DNAT Risk Ports Check",
		"zh": "NAT 网关 DNAT 条目禁用高风险端口",
		"ja": "NAT ゲートウェイ DNAT リスクポートチェック",
		"de": "NAT-Gateway DNAT Risikoport-Prüfung",
		"es": "Verificación de Puertos de Riesgo DNAT de Puerta de Enlace NAT",
		"fr": "Vérification des Ports à Risque DNAT de Passerelle NAT",
		"pt": "Verificação de Portas de Risco DNAT do Gateway NAT"
	},
	"description": {
		"en": "Ensures NAT gateway DNAT entries do not expose high-risk ports.",
		"zh": "确保 NAT 网关 DNAT 条目未暴露高风险端口。",
		"ja": "NAT ゲートウェイ DNAT エントリがリスクポートを公開していないことを確認します。",
		"de": "Stellt sicher, dass NAT-Gateway-DNAT-Einträge keine Hochrisiko-Ports freigeben.",
		"es": "Garantiza que las entradas DNAT de la puerta de enlace NAT no expongan puertos de alto riesgo.",
		"fr": "Garantit que les entrées DNAT de la passerelle NAT n'exposent pas de ports à haut risque.",
		"pt": "Garante que as entradas DNAT do gateway NAT não exponham portas de alto risco."
	},
	"reason": {
		"en": "Exposing management and database ports via DNAT increases the risk of unauthorized access and attacks.",
		"zh": "通过 DNAT 暴露管理和数据库端口会增加未经授权访问和攻击的风险。",
		"ja": "DNAT を介して管理ポートやデータベースポートを公開すると、不正アクセスや攻撃のリスクが増加します。",
		"de": "Das Freigeben von Verwaltungs- und Datenbankports über DNAT erhöht das Risiko unbefugten Zugriffs und von Angriffen.",
		"es": "Exponer puertos de administración y base de datos a través de DNAT aumenta el riesgo de acceso no autorizado y ataques.",
		"fr": "Exposer les ports de gestion et de base de données via DNAT augmente le risque d'accès non autorisé et d'attaques.",
		"pt": "Expor portas de gerenciamento e banco de dados via DNAT aumenta o risco de acesso não autorizado e ataques."
	},
	"recommendation": {
		"en": "Change external_port to a non-risky port, or use a VPN/Bastion Host for management access.",
		"zh": "将 external_port 更改为非高风险端口，或使用 VPN/堡垒机进行管理访问。",
		"ja": "external_port を非リスクポートに変更するか、管理アクセスには VPN/バスティオンホストを使用します。",
		"de": "Ändern Sie external_port auf einen nicht riskanten Port oder verwenden Sie ein VPN/Bastion Host für den Verwaltungszugriff.",
		"es": "Cambie external_port a un puerto no riesgoso, o use un VPN/Host Bastión para acceso de administración.",
		"fr": "Changez external_port vers un port non risqué, ou utilisez un VPN/Hôte Bastion pour l'accès de gestion.",
		"pt": "Altere external_port para uma porta não arriscada, ou use VPN/Host Bastião para acesso de gerenciamento."
	},
	"resource_types": ["alicloud_forward_entry"],
	"iac_type": "terraform"
}

risky_ports := {"22", "23", "445", "3389", "1433", "3306", "5432", "6379", "8080", "8443"}

is_compliant(resource) if {
	port := tf.get_attribute(resource, "external_port", "")
	not tf.is_unknown(port)
	not port in risky_ports
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_forward_entry")
	not is_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_forward_entry.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
