package infraguard.rules.aliyun.mongodb_instance_class_not_shared

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-instance-class-not-shared",
	"name": {
		"en": "MongoDB Instance Uses Dedicated Class",
		"zh": "MongoDB 使用独享型或专属型规格实例",
		"ja": "MongoDB インスタンスが専用クラスを使用",
		"de": "MongoDB-Instanz verwendet dedizierte Klasse",
		"es": "Instancia MongoDB Usa Clase Dedicada",
		"fr": "L'Instance MongoDB Utilise une Classe Dédiée",
		"pt": "Instância MongoDB Usa Classe Dedicada",
	},
	"severity": "high",
	"description": {
		"en": "Ensures MongoDB instances use dedicated or exclusive instance classes, not shared instances.",
		"zh": "确保 MongoDB 实例使用独享型或专属型规格实例，而非共享型实例。",
		"ja": "MongoDB インスタンスが共有インスタンスではなく、専用または専属インスタンスクラスを使用していることを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen dedizierte oder exklusive Instanzklassen verwenden, keine gemeinsam genutzten Instanzen.",
		"es": "Garantiza que las instancias MongoDB usen clases de instancia dedicadas o exclusivas, no instancias compartidas.",
		"fr": "Garantit que les instances MongoDB utilisent des classes d'instance dédiées ou exclusives, et non des instances partagées.",
		"pt": "Garante que as instâncias MongoDB usem classes de instância dedicadas ou exclusivas, não instâncias compartilhadas.",
	},
	"reason": {
		"en": "Shared instance classes may have resource contention issues, affecting database performance and stability.",
		"zh": "共享型实例规格可能存在资源争用问题，影响数据库性能和稳定性。",
		"ja": "共有インスタンスクラスにはリソース競合の問題があり、データベースのパフォーマンスと安定性に影響を与える可能性があります。",
		"de": "Gemeinsam genutzte Instanzklassen können Ressourcenkonfliktprobleme haben, die die Datenbankleistung und -stabilität beeinträchtigen.",
		"es": "Las clases de instancia compartidas pueden tener problemas de contención de recursos, afectando el rendimiento y la estabilidad de la base de datos.",
		"fr": "Les classes d'instance partagées peuvent avoir des problèmes de contention de ressources, affectant les performances et la stabilité de la base de données.",
		"pt": "As classes de instância compartilhadas podem ter problemas de contenção de recursos, afetando o desempenho e a estabilidade do banco de dados.",
	},
	"recommendation": {
		"en": "Use dedicated or exclusive instance classes for MongoDB instances.",
		"zh": "为 MongoDB 实例使用独享型或专属型规格实例。",
		"ja": "MongoDB インスタンスに専用または専属インスタンスクラスを使用します。",
		"de": "Verwenden Sie dedizierte oder exklusive Instanzklassen für MongoDB-Instanzen.",
		"es": "Use clases de instancia dedicadas o exclusivas para instancias MongoDB.",
		"fr": "Utilisez des classes d'instance dédiées ou exclusives pour les instances MongoDB.",
		"pt": "Use classes de instância dedicadas ou exclusivas para instâncias MongoDB.",
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"],
}

# Shared instance class patterns (these are typically shared types)
shared_classes := {
	"dds.mongo.sharding",
	"dds.mongo.logic",
	"dds.mongo.shared",
}

# Check if instance class is not shared
is_compliant(resource) if {
	instance_class := helpers.get_property(resource, "DBInstanceClass", "")
	not contains_shared_class(lower(instance_class))
}

contains_shared_class(instance_class) if {
	some shared_class in shared_classes
	contains(instance_class, shared_class)
}

deny contains result if {
	some name, resource in helpers.resources_by_types(rule_meta.resource_types)
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "DBInstanceClass"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
