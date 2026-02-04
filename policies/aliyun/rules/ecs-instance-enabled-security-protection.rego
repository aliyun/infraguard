package infraguard.rules.aliyun.ecs_instance_enabled_security_protection

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-enabled-security-protection",
	"name": {
		"en": "ECS Instance Enabled Security Protection",
		"zh": "运行中的 ECS 实例开启云安全中心防护",
		"ja": "ECS インスタンスでセキュリティ保護が有効",
		"de": "ECS-Instanz Sicherheitsschutz aktiviert",
		"es": "Protección de Seguridad de Instancia ECS Habilitada",
		"fr": "Protection de Sécurité d'Instance ECS Activée",
		"pt": "Proteção de Segurança de Instância ECS Habilitada",
	},
	"severity": "high",
	"description": {
		"en": "Ensures that ECS instances have security enhancement strategy enabled.",
		"zh": "确保 ECS 实例开启了安全增强策略（云安全中心防护）。",
		"ja": "ECS インスタンスでセキュリティ強化戦略が有効になっていることを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen Sicherheitsverbesserungsstrategie aktiviert haben.",
		"es": "Garantiza que las instancias ECS tengan estrategia de mejora de seguridad habilitada.",
		"fr": "Garantit que les instances ECS ont la stratégie d'amélioration de la sécurité activée.",
		"pt": "Garante que as instâncias ECS tenham estratégia de aprimoramento de segurança habilitada.",
	},
	"reason": {
		"en": "Without security protection, the instance is more vulnerable to attacks and malware.",
		"zh": "如果没有安全防护，实例更容易受到攻击和恶意软件的侵害。",
		"ja": "セキュリティ保護がない場合、インスタンスは攻撃やマルウェアに対してより脆弱になります。",
		"de": "Ohne Sicherheitsschutz ist die Instanz anfälliger für Angriffe und Malware.",
		"es": "Sin protección de seguridad, la instancia es más vulnerable a ataques y malware.",
		"fr": "Sans protection de sécurité, l'instance est plus vulnérable aux attaques et aux logiciels malveillants.",
		"pt": "Sem proteção de segurança, a instância é mais vulnerável a ataques e malware.",
	},
	"recommendation": {
		"en": "Enable security enhancement strategy for the ECS instance by setting SecurityEnhancementStrategy to 'Active'.",
		"zh": "通过将 SecurityEnhancementStrategy 设置为 'Active' 为 ECS 实例开启安全增强策略。",
		"ja": "SecurityEnhancementStrategy を 'Active' に設定して、ECS インスタンスでセキュリティ強化戦略を有効にします。",
		"de": "Aktivieren Sie die Sicherheitsverbesserungsstrategie für die ECS-Instanz, indem Sie SecurityEnhancementStrategy auf 'Active' setzen.",
		"es": "Habilite la estrategia de mejora de seguridad para la instancia ECS estableciendo SecurityEnhancementStrategy en 'Active'.",
		"fr": "Activez la stratégie d'amélioration de la sécurité pour l'instance ECS en définissant SecurityEnhancementStrategy sur 'Active'.",
		"pt": "Habilite estratégia de aprimoramento de segurança para a instância ECS definindo SecurityEnhancementStrategy como 'Active'.",
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"],
}

is_compliant(resource) if {
	helpers.get_property(resource, "SecurityEnhancementStrategy", "Active") == "Active"
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityEnhancementStrategy"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
