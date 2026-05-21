package infraguard.rules.aliyun.ecs_launch_template_version_attach_security_group

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-launch-template-version-attach-security-group",
	"severity": "high",
	"name": {
		"en": "ECS launch template version attaches security groups",
		"zh": "ECS 启动模版版本中设置加入的安全组",
		"ja": "ECS 起動テンプレートバージョンがセキュリティグループをアタッチ",
		"de": "ECS-Startvorlagenversion fügt Sicherheitsgruppen hinzu",
		"es": "La Versión de Plantilla de Inicio ECS Adjunta Grupos de Seguridad",
		"fr": "La Version du Modèle de Démarrage ECS Attache les Groupes de Sécurité",
		"pt": "Versão do Modelo de Inicialização ECS Anexa Grupos de Segurança"
	},
	"description": {
		"en": "ECS launch template versions have security groups configured for instances, considered compliant.",
		"zh": "ECS 启动模版版本中设置了实例要加入的安全组，视为合规。",
		"ja": "ECS 起動テンプレートバージョンにインスタンス用のセキュリティグループが設定されており、準拠と見なされます。",
		"de": "ECS-Startvorlagenversionen haben Sicherheitsgruppen für Instanzen konfiguriert, was als konform gilt.",
		"es": "Las versiones de plantilla de inicio ECS tienen grupos de seguridad configurados para instancias, considerado conforme.",
		"fr": "Les versions de modèle de démarrage ECS ont des groupes de sécurité configurés pour les instances, considéré comme conforme.",
		"pt": "As versões do modelo de inicialização ECS têm grupos de segurança configurados para instâncias, considerado conforme."
	},
	"reason": {
		"en": "ECS launch template version does not have security groups configured",
		"zh": "ECS 启动模板版本未配置安全组",
		"ja": "ECS 起動テンプレートバージョンにセキュリティグループが設定されていません",
		"de": "ECS-Startvorlagenversion hat keine Sicherheitsgruppen konfiguriert",
		"es": "La versión de plantilla de inicio ECS no tiene grupos de seguridad configurados",
		"fr": "La version du modèle de démarrage ECS n'a pas de groupes de sécurité configurés",
		"pt": "A versão do modelo de inicialização ECS não tem grupos de segurança configurados"
	},
	"recommendation": {
		"en": "Configure security groups in launch template versions for instance network security",
		"zh": "在启动模板版本中配置安全组以确保实例网络安全",
		"ja": "インスタンスネットワークセキュリティのために起動テンプレートバージョンでセキュリティグループを設定します",
		"de": "Konfigurieren Sie Sicherheitsgruppen in Startvorlagenversionen für die Instanznetzwerksicherheit",
		"es": "Configure grupos de seguridad en versiones de plantilla de inicio para la seguridad de red de instancias",
		"fr": "Configurez les groupes de sécurité dans les versions de modèle de démarrage pour la sécurité réseau des instances",
		"pt": "Configure grupos de segurança nas versões do modelo de inicialização para segurança de rede da instância"
	},
	"resource_types": ["ALIYUN::ECS::LaunchTemplate"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::LaunchTemplate")

	# Check if security group is configured
	security_group_id := helpers.get_property(resource, "SecurityGroupId", "")
	security_group_ids := helpers.get_property(resource, "SecurityGroupIds", [])

	# Neither SecurityGroupId nor SecurityGroupIds is specified
	security_group_id == ""
	count(security_group_ids) == 0

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupId"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
