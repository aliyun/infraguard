package infraguard.rules.terraform.mongodb_instance_class_not_shared

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-instance-class-not-shared",
	"severity": "medium",
	"name": {
		"en": "MongoDB Instance Class Not Shared",
		"zh": "MongoDB 实例规格非共享型",
		"ja": "MongoDB インスタンスが専用クラスを使用",
		"de": "MongoDB-Instanz verwendet dedizierte Klasse",
		"es": "Instancia MongoDB Usa Clase Dedicada",
		"fr": "L'Instance MongoDB Utilise une Classe Dédiée",
		"pt": "Instância MongoDB Usa Classe Dedicada"
	},
	"description": {
		"en": "MongoDB instance class should not be shared type; dedicated instances provide better performance isolation.",
		"zh": "MongoDB 实例规格不应为共享型，独享型实例提供更好的性能隔离。",
		"ja": "MongoDB インスタンスが共有インスタンスではなく、専用または専属インスタンスクラスを使用していることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen dedizierte oder exklusive Instanzklassen verwenden, keine gemeinsam genutzten Instanzen.",
		"es": "Garantiza que las instancias MongoDB usen clases de instancia dedicadas o exclusivas, no instancias compartidas.",
		"fr": "Garantit que les instances MongoDB utilisent des classes d'instance dédiées ou exclusives, et non des instances partagées.",
		"pt": "Garante que as instâncias MongoDB usem classes de instância dedicadas ou exclusivas, não instâncias compartilhadas."
	},
	"reason": {
		"en": "The MongoDB instance is using a shared instance class.",
		"zh": "MongoDB 实例使用了共享型规格。",
		"ja": "共有インスタンスクラスにはリソース競合の問題があり、データベースのパフォーマンスと安定性に影響を与える可能性があります。",
		"de": "Gemeinsam genutzte Instanzklassen können Ressourcenkonfliktprobleme haben, die die Datenbankleistung und -stabilität beeinträchtigen.",
		"es": "Las clases de instancia compartidas pueden tener problemas de contención de recursos, afectando el rendimiento y la estabilidad de la base de datos.",
		"fr": "Les classes d'instance partagées peuvent avoir des problèmes de contention de ressources, affectant les performances et la stabilité de la base de données.",
		"pt": "As classes de instância compartilhadas podem ter problemas de contenção de recursos, afetando o desempenho e a estabilidade do banco de dados."
	},
	"recommendation": {
		"en": "Use a dedicated instance class (one that does not contain 'shared' in the name).",
		"zh": "使用独享型实例规格（名称中不包含 'shared'）。",
		"ja": "MongoDB インスタンスに専用または専属インスタンスクラスを使用します。",
		"de": "Verwenden Sie dedizierte oder exklusive Instanzklassen für MongoDB-Instanzen.",
		"es": "Use clases de instancia dedicadas o exclusivas para instancias MongoDB.",
		"fr": "Utilisez des classes d'instance dédiées ou exclusives pour les instances MongoDB.",
		"pt": "Use classes de instância dedicadas ou exclusivas para instâncias MongoDB."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	db_class := tf.get_attribute(resource, "db_instance_class", "")
	contains(db_class, "shared")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
