package infraguard.rules.terraform.mse_cluster_multi_availability_area_architecture_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "MSE cluster should use mse_pro version with instance_count >= 3 and an odd number for multi-AZ deployment.",
		"zh": "MSE 集群应使用 mse_pro 版本，且 instance_count >= 3 并为奇数，以实现多可用区部署。",
		"ja": "MSE クラスターは高可用性のために少なくとも 3 つのインスタンス（奇数）を持つプロフェッショナル版を使用する必要があります。",
		"de": "MSE-Cluster sollten die Professional Edition mit mindestens 3 Instanzen (ungerade Zahl) für Hochverfügbarkeit verwenden.",
		"es": "Los clústeres MSE deben usar la Edición Profesional con al menos 3 instancias (número impar) para alta disponibilidad.",
		"fr": "Les clusters MSE doivent utiliser l'Édition Professionnelle avec au moins 3 instances (nombre impair) pour une haute disponibilité.",
		"pt": "Os clusters MSE devem usar a Edição Profissional com pelo menos 3 instâncias (número ímpar) para alta disponibilidade."
	},
	"reason": {
		"en": "The MSE cluster does not meet multi-availability zone architecture requirements (mse_pro, instance_count >= 3, odd).",
		"zh": "MSE 集群不满足多可用区架构要求（mse_pro 版本、instance_count >= 3 且为奇数）。",
		"ja": "MSE クラスターが高可用性要件を満たしていません（プロフェッショナル版では InstanceCount >= 3 かつ奇数が必要）。",
		"de": "Der MSE-Cluster erfüllt nicht die Hochverfügbarkeitsanforderungen (Professional Edition erfordert InstanceCount >= 3 und ungerade Zahl).",
		"es": "El clúster MSE no cumple con los requisitos de alta disponibilidad (la Edición Profesional requiere InstanceCount >= 3 y número impar).",
		"fr": "Le cluster MSE ne répond pas aux exigences de haute disponibilité (l'Édition Professionnelle nécessite InstanceCount >= 3 et nombre impair).",
		"pt": "O cluster MSE não atende aos requisitos de alta disponibilidade (a Edição Profissional requer InstanceCount >= 3 e número ímpar)."
	},
	"recommendation": {
		"en": "Set mse_version to 'mse_pro' and instance_count to an odd number >= 3.",
		"zh": "将 mse_version 设置为 'mse_pro'，instance_count 设置为 >= 3 的奇数。",
		"ja": "プロフェッショナル版（MseVersion: mse_pro）を使用し、高可用性のために InstanceCount を少なくとも 3（奇数）に設定します。",
		"de": "Verwenden Sie die Professional Edition (MseVersion: mse_pro) und setzen Sie InstanceCount auf mindestens 3 (ungerade Zahl) für Hochverfügbarkeit.",
		"es": "Use la Edición Profesional (MseVersion: mse_pro) y establezca InstanceCount en al menos 3 (número impar) para alta disponibilidad.",
		"fr": "Utilisez l'Édition Professionnelle (MseVersion: mse_pro) et définissez InstanceCount sur au moins 3 (nombre impair) pour une haute disponibilité.",
		"pt": "Use a Edição Profissional (MseVersion: mse_pro) e defina InstanceCount para pelo menos 3 (número ímpar) para alta disponibilidade."
	},
	"resource_types": ["alicloud_mse_cluster"],
	"iac_type": "terraform"
}

is_multi_az_compliant(resource) if {
	mse_version := tf.get_attribute(resource, "mse_version", "")
	mse_version == "mse_pro"
	instance_count := tf.get_attribute(resource, "instance_count", 0)
	instance_count >= 3
	instance_count % 2 == 1
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mse_cluster")
	not is_multi_az_compliant(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mse_cluster.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
