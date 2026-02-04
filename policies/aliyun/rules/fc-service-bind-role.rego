package infraguard.rules.aliyun.fc_service_bind_role

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-service-bind-role",
	"severity": "medium",
	"name": {
		"en": "FC Service Bound to RAM Role",
		"zh": "FC 服务绑定角色",
		"ja": "FC サービスが RAM ロールにバインドされている",
		"de": "FC-Service an RAM-Rolle gebunden",
		"es": "Servicio FC Vinculado a Rol RAM",
		"fr": "Service FC Lié au Rôle RAM",
		"pt": "Serviço FC Vinculado à Função RAM"
	},
	"description": {
		"en": "Ensures that the Function Compute service has a RAM role bound to it.",
		"zh": "确保函数计算服务绑定了 RAM 角色。",
		"ja": "関数計算サービスに RAM ロールがバインドされていることを確認します。",
		"de": "Stellt sicher, dass der Function Compute-Service eine RAM-Rolle gebunden hat.",
		"es": "Garantiza que el servicio Function Compute tenga un rol RAM vinculado.",
		"fr": "Garantit que le service Function Compute a un rôle RAM lié.",
		"pt": "Garante que o serviço Function Compute tenha uma função RAM vinculada."
	},
	"reason": {
		"en": "Binding a RAM role to an FC service allows the function to securely access other Alibaba Cloud resources.",
		"zh": "为 FC 服务绑定 RAM 角色允许函数安全地访问其他阿里云资源。",
		"ja": "FC サービスに RAM ロールをバインドすることで、関数が他の Alibaba Cloud リソースに安全にアクセスできるようになります。",
		"de": "Das Binden einer RAM-Rolle an einen FC-Service ermöglicht es der Funktion, sicher auf andere Alibaba Cloud-Ressourcen zuzugreifen.",
		"es": "Vincular un rol RAM a un servicio FC permite que la función acceda de forma segura a otros recursos de Alibaba Cloud.",
		"fr": "Lier un rôle RAM à un service FC permet à la fonction d'accéder en toute sécurité à d'autres ressources Alibaba Cloud.",
		"pt": "Vincular uma função RAM a um serviço FC permite que a função acesse com segurança outros recursos da Alibaba Cloud."
	},
	"recommendation": {
		"en": "Bind a RAM role to the Function Compute service.",
		"zh": "为函数计算服务绑定 RAM 角色。",
		"ja": "関数計算サービスに RAM ロールをバインドします。",
		"de": "Binden Sie eine RAM-Rolle an den Function Compute-Service.",
		"es": "Vincule un rol RAM al servicio Function Compute.",
		"fr": "Lieez un rôle RAM au service Function Compute.",
		"pt": "Vincule uma função RAM ao serviço Function Compute."
	},
	"resource_types": ["ALIYUN::FC::Service"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	not helpers.has_property(resource, "Role")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Role"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
