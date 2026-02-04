package infraguard.rules.aliyun.rds_instance_has_guard_instance

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "rds-instance-has-guard-instance",
	"name": {
		"en": "RDS Instance Has Guard Instance",
		"zh": "RDS 关键实例配置灾备实例",
		"ja": "RDS インスタンスにガードインスタンスがある",
		"de": "RDS-Instanz hat Guard-Instanz",
		"es": "La Instancia RDS Tiene Instancia de Guardia",
		"fr": "L'Instance RDS a une Instance de Garde",
		"pt": "A Instância RDS Tem Instância de Guarda",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures production RDS instances have a corresponding guard (disaster recovery) instance.",
		"zh": "确保生产环境 RDS 实例配置了相应的灾备实例。",
		"ja": "本番環境の RDS インスタンスに対応するガード（災害復旧）インスタンスがあることを確認します。",
		"de": "Stellt sicher, dass Produktions-RDS-Instanzen eine entsprechende Guard-Instanz (Notfallwiederherstellung) haben.",
		"es": "Garantiza que las instancias RDS de producción tengan una instancia de guardia (recuperación ante desastres) correspondiente.",
		"fr": "Garantit que les instances RDS de production ont une instance de garde (récupération après sinistre) correspondante.",
		"pt": "Garante que as instâncias RDS de produção tenham uma instância de guarda (recuperação de desastres) correspondente.",
	},
	"reason": {
		"en": "Guard instances provide high availability and data redundancy across regions.",
		"zh": "灾备实例提供跨地域的高可用性和数据冗余。",
		"ja": "ガードインスタンスは、リージョン全体で高可用性とデータ冗長性を提供します。",
		"de": "Guard-Instanzen bieten Hochverfügbarkeit und Datenredundanz über Regionen hinweg.",
		"es": "Las instancias de guardia proporcionan alta disponibilidad y redundancia de datos entre regiones.",
		"fr": "Les instances de garde offrent une haute disponibilité et une redondance des données entre les régions.",
		"pt": "As instâncias de guarda fornecem alta disponibilidade e redundância de dados entre regiões.",
	},
	"recommendation": {
		"en": "Configure a guard instance for the primary RDS instance.",
		"zh": "为主要 RDS 实例配置灾备实例。",
		"ja": "プライマリ RDS インスタンスのガードインスタンスを設定します。",
		"de": "Konfigurieren Sie eine Guard-Instanz für die primäre RDS-Instanz.",
		"es": "Configure una instancia de guardia para la instancia RDS principal.",
		"fr": "Configurez une instance de garde pour l'instance RDS principale.",
		"pt": "Configure uma instância de guarda para a instância RDS principal.",
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"],
}

# Cross-resource check: is there another RDS instance or DR resource linked?
# Simplified for static check: check if it's a high availability category
is_compliant(resource) if {
	cat := helpers.get_property(resource, "Category", "")
	helpers.includes(["HighAvailability", "cluster", "AlwaysOn", "Finance"], cat)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Category"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
