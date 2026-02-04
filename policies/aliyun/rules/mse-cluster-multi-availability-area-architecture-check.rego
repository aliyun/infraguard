package infraguard.rules.aliyun.mse_cluster_multi_availability_area_architecture_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "mse-cluster-multi-availability-area-architecture-check",
	"severity": "medium",
	"name": {
		"en": "MSE Cluster High-Availability Configuration",
		"zh": "使用高可用版本的 MSE 注册配置中心",
		"ja": "MSE クラスター高可用性設定",
		"de": "MSE-Cluster Hochverfügbarkeitskonfiguration",
		"es": "Configuración de Alta Disponibilidad del Clúster MSE",
		"fr": "Configuration de Haute Disponibilité du Cluster MSE",
		"pt": "Configuração de Alta Disponibilidade do Cluster MSE"
	},
	"description": {
		"en": "MSE clusters should use the Professional Edition with at least 3 instances (odd number) for high availability.",
		"zh": "使用高可用版本的 MSE 注册配置中心，视为合规。",
		"ja": "MSE クラスターは高可用性のために少なくとも 3 つのインスタンス（奇数）を持つプロフェッショナル版を使用する必要があります。",
		"de": "MSE-Cluster sollten die Professional Edition mit mindestens 3 Instanzen (ungerade Zahl) für Hochverfügbarkeit verwenden.",
		"es": "Los clústeres MSE deben usar la Edición Profesional con al menos 3 instancias (número impar) para alta disponibilidad.",
		"fr": "Les clusters MSE doivent utiliser l'Édition Professionnelle avec au moins 3 instances (nombre impair) pour une haute disponibilité.",
		"pt": "Os clusters MSE devem usar a Edição Profissional com pelo menos 3 instâncias (número ímpar) para alta disponibilidade."
	},
	"reason": {
		"en": "The MSE cluster does not meet high-availability requirements (Professional Edition requires InstanceCount >= 3 and odd number).",
		"zh": "MSE 集群不满足高可用性要求（专业版要求 InstanceCount >= 3 且为奇数）。",
		"ja": "MSE クラスターが高可用性要件を満たしていません（プロフェッショナル版では InstanceCount >= 3 かつ奇数が必要）。",
		"de": "Der MSE-Cluster erfüllt nicht die Hochverfügbarkeitsanforderungen (Professional Edition erfordert InstanceCount >= 3 und ungerade Zahl).",
		"es": "El clúster MSE no cumple con los requisitos de alta disponibilidad (la Edición Profesional requiere InstanceCount >= 3 y número impar).",
		"fr": "Le cluster MSE ne répond pas aux exigences de haute disponibilité (l'Édition Professionnelle nécessite InstanceCount >= 3 et nombre impair).",
		"pt": "O cluster MSE não atende aos requisitos de alta disponibilidade (a Edição Profissional requer InstanceCount >= 3 e número ímpar)."
	},
	"recommendation": {
		"en": "Use Professional Edition (MseVersion: mse_pro) and set InstanceCount to at least 3 (odd number) for high availability.",
		"zh": "使用专业版（MseVersion: mse_pro）并将 InstanceCount 设置为至少 3（奇数）以实现高可用性。",
		"ja": "プロフェッショナル版（MseVersion: mse_pro）を使用し、高可用性のために InstanceCount を少なくとも 3（奇数）に設定します。",
		"de": "Verwenden Sie die Professional Edition (MseVersion: mse_pro) und setzen Sie InstanceCount auf mindestens 3 (ungerade Zahl) für Hochverfügbarkeit.",
		"es": "Use la Edición Profesional (MseVersion: mse_pro) y establezca InstanceCount en al menos 3 (número impar) para alta disponibilidad.",
		"fr": "Utilisez l'Édition Professionnelle (MseVersion: mse_pro) et définissez InstanceCount sur au moins 3 (nombre impair) pour une haute disponibilité.",
		"pt": "Use a Edição Profissional (MseVersion: mse_pro) e defina InstanceCount para pelo menos 3 (número ímpar) para alta disponibilidade."
	},
	"resource_types": ["ALIYUN::MSE::Cluster"]
}

# Check if cluster is Professional Edition
is_professional_edition(resource) if {
	helpers.has_property(resource, "MseVersion")
	mse_version := resource.Properties.MseVersion
	mse_version == "mse_pro"
}

# Check if instance count meets HA requirements (>= 3 and odd)
has_ha_instance_count(resource) if {
	instance_count := resource.Properties.InstanceCount
	instance_count >= 3
	instance_count % 2 == 1
}

# Check if cluster is high availability
is_high_availability(resource) if {
	is_professional_edition(resource)
	has_ha_instance_count(resource)
}

# Deny rule: MSE clusters should be high availability
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MSE::Cluster")
	not is_high_availability(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
