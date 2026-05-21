package infraguard.rules.aliyun.ecs_instance_ram_role_attached

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ecs-instance-ram-role-attached",
	"severity": "low",
	"name": {
		"en": "ECS Instance RAM Role Attached",
		"zh": "ECS 实例被授予实例 RAM 角色",
		"ja": "ECS インスタンスに RAM ロールがアタッチされている",
		"de": "ECS-Instanz RAM-Rolle angehängt",
		"es": "Rol RAM de Instancia ECS Adjunto",
		"fr": "Rôle RAM d'Instance ECS Attaché",
		"pt": "Função RAM de Instância ECS Anexada"
	},
	"description": {
		"en": "Ensures that ECS instances have an IAM role attached for secure access to other cloud services.",
		"zh": "确保 ECS 实例被授予了实例 RAM 角色，以便安全地访问其他云服务。",
		"ja": "ECS インスタンスに IAM ロールがアタッチされ、他のクラウドサービスに安全にアクセスできることを確認します。",
		"de": "Stellt sicher, dass ECS-Instanzen eine IAM-Rolle angehängt haben, um sicher auf andere Cloud-Dienste zuzugreifen.",
		"es": "Garantiza que las instancias ECS tengan un rol IAM adjunto para acceso seguro a otros servicios en la nube.",
		"fr": "Garantit que les instances ECS ont un rôle IAM attaché pour un accès sécurisé aux autres services cloud.",
		"pt": "Garante que as instâncias ECS tenham uma função IAM anexada para acesso seguro a outros serviços em nuvem."
	},
	"reason": {
		"en": "Using RAM roles instead of hardcoded AccessKeys improves security by providing temporary credentials.",
		"zh": "使用 RAM 角色代替硬编码的 AccessKey，通过提供临时凭证来提高安全性。",
		"ja": "ハードコードされた AccessKey の代わりに RAM ロールを使用することで、一時的な認証情報を提供してセキュリティを向上させます。",
		"de": "Die Verwendung von RAM-Rollen anstelle von hartcodierten AccessKeys verbessert die Sicherheit durch Bereitstellung temporärer Anmeldeinformationen.",
		"es": "Usar roles RAM en lugar de AccessKeys codificadas mejora la seguridad al proporcionar credenciales temporales.",
		"fr": "Utiliser des rôles RAM au lieu d'AccessKeys codées en dur améliore la sécurité en fournissant des identifiants temporaires.",
		"pt": "Usar funções RAM em vez de AccessKeys codificadas melhora a segurança fornecendo credenciais temporárias."
	},
	"recommendation": {
		"en": "Attach a RAM role to the ECS instance.",
		"zh": "为 ECS 实例授予 RAM 角色。",
		"ja": "ECS インスタンスに RAM ロールをアタッチします。",
		"de": "Hängen Sie eine RAM-Rolle an die ECS-Instanz an.",
		"es": "Adjunte un rol RAM a la instancia ECS.",
		"fr": "Attachez un rôle RAM à l'instance ECS.",
		"pt": "Anexe uma função RAM à instância ECS."
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"]
}

# Check if instance has RAM role attached
has_ram_role(resource) if {
	helpers.has_property(resource, "RamRoleName")
	role := resource.Properties.RamRoleName
	role != ""
}

# Deny rule: ECS instances should have RAM role attached
deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	not has_ram_role(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "RamRoleName"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
