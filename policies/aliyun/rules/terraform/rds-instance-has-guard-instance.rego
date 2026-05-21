package infraguard.rules.terraform.rds_instance_has_guard_instance

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "rds-instance-has-guard-instance",
	"severity": "medium",
	"name": {
		"en": "RDS Instance Has Guard Instance",
		"zh": "RDS 关键实例配置灾备实例",
		"ja": "RDS インスタンスにガードインスタンスがある",
		"de": "RDS-Instanz hat Guard-Instanz",
		"es": "La Instancia RDS Tiene Instancia de Guardia",
		"fr": "L'Instance RDS a une Instance de Garde",
		"pt": "A Instância RDS Tem Instância de Guarda"
	},
	"description": {
		"en": "Ensures production RDS instances have a high availability category configured.",
		"zh": "确保生产环境 RDS 实例配置了高可用类别。",
		"ja": "本番環境の RDS インスタンスに高可用性カテゴリが設定されていることを確認します。",
		"de": "Stellt sicher, dass Produktions-RDS-Instanzen eine Hochverfügbarkeitskategorie konfiguriert haben.",
		"es": "Garantiza que las instancias RDS de producción tengan una categoría de alta disponibilidad configurada.",
		"fr": "Garantit que les instances RDS de production ont une catégorie de haute disponibilité configurée.",
		"pt": "Garante que as instâncias RDS de produção tenham uma categoria de alta disponibilidade configurada."
	},
	"reason": {
		"en": "Guard instances provide high availability and data redundancy across regions.",
		"zh": "灾备实例提供跨地域的高可用性和数据冗余。",
		"ja": "ガードインスタンスは、リージョン全体で高可用性とデータ冗長性を提供します。",
		"de": "Guard-Instanzen bieten Hochverfügbarkeit und Datenredundanz über Regionen hinweg.",
		"es": "Las instancias de guardia proporcionan alta disponibilidad y redundancia de datos entre regiones.",
		"fr": "Les instances de garde offrent une haute disponibilité et une redondance des données entre les régions.",
		"pt": "As instâncias de guarda fornecem alta disponibilidade e redundância de dados entre regiões."
	},
	"recommendation": {
		"en": "Set category to \"HighAvailability\", \"cluster\", \"AlwaysOn\", or \"Finance\" for the RDS instance.",
		"zh": "为 RDS 实例将 category 设置为 \"HighAvailability\"、\"cluster\"、\"AlwaysOn\" 或 \"Finance\"。",
		"ja": "RDS インスタンスの category を \"HighAvailability\"、\"cluster\"、\"AlwaysOn\"、または \"Finance\" に設定します。",
		"de": "Setzen Sie category für die RDS-Instanz auf \"HighAvailability\", \"cluster\", \"AlwaysOn\" oder \"Finance\".",
		"es": "Establezca category en \"HighAvailability\", \"cluster\", \"AlwaysOn\" o \"Finance\" para la instancia RDS.",
		"fr": "Définissez category sur \"HighAvailability\", \"cluster\", \"AlwaysOn\" ou \"Finance\" pour l'instance RDS.",
		"pt": "Defina category como \"HighAvailability\", \"cluster\", \"AlwaysOn\" ou \"Finance\" para a instância RDS."
	},
	"resource_types": ["alicloud_db_instance"],
	"iac_type": "terraform"
}

ha_categories := {"HighAvailability", "cluster", "AlwaysOn", "Finance"}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_instance")
	cat := tf.get_attribute(resource, "category", "")
	not cat in ha_categories
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
