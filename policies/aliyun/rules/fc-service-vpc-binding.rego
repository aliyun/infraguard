package infraguard.rules.aliyun.fc_service_vpc_binding

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "fc-service-vpc-binding",
	"severity": "medium",
	"name": {
		"en": "FC Service VPC Binding Enabled",
		"zh": "FC 服务绑定 VPC",
		"ja": "FC サービス VPC バインディングが有効",
		"de": "FC-Service VPC-Bindung aktiviert",
		"es": "Vinculación VPC del Servicio FC Habilitada",
		"fr": "Liaison VPC du Service FC Activée",
		"pt": "Vinculação VPC do Serviço FC Habilitada"
	},
	"description": {
		"en": "Ensures that the Function Compute service is configured to access resources within a VPC.",
		"zh": "确保函数计算服务已配置为访问 VPC 内的资源。",
		"ja": "関数計算サービスが VPC 内のリソースにアクセスするように設定されていることを確認します。",
		"de": "Stellt sicher, dass der Function Compute-Service so konfiguriert ist, dass er auf Ressourcen innerhalb eines VPC zugreift.",
		"es": "Garantiza que el servicio Function Compute esté configurado para acceder a recursos dentro de un VPC.",
		"fr": "Garantit que le service Function Compute est configuré pour accéder aux ressources dans un VPC.",
		"pt": "Garante que o serviço Function Compute esteja configurado para acessar recursos dentro de um VPC."
	},
	"reason": {
		"en": "Binding a VPC to an FC service allows functions to securely access internal resources like databases and internal APIs.",
		"zh": "为 FC 服务绑定 VPC 允许函数安全地访问内网资源，如数据库和内部 API。",
		"ja": "VPC を FC サービスにバインドすると、関数がデータベースや内部 API などの内部リソースに安全にアクセスできます。",
		"de": "Das Binden eines VPC an einen FC-Service ermöglicht es Funktionen, sicher auf interne Ressourcen wie Datenbanken und interne APIs zuzugreifen.",
		"es": "Vincular un VPC a un servicio FC permite que las funciones accedan de forma segura a recursos internos como bases de datos y APIs internas.",
		"fr": "Lier un VPC à un service FC permet aux fonctions d'accéder en toute sécurité aux ressources internes telles que les bases de données et les API internes.",
		"pt": "Vincular um VPC a um serviço FC permite que as funções acessem com segurança recursos internos como bancos de dados e APIs internas."
	},
	"recommendation": {
		"en": "Configure VPC access for the Function Compute service.",
		"zh": "为函数计算服务配置 VPC 访问。",
		"ja": "関数計算サービスの VPC アクセスを設定します。",
		"de": "Konfigurieren Sie den VPC-Zugriff für den Function Compute-Service.",
		"es": "Configure el acceso VPC para el servicio Function Compute.",
		"fr": "Configurez l'accès VPC pour le service Function Compute.",
		"pt": "Configure o acesso VPC para o serviço Function Compute."
	},
	"resource_types": ["ALIYUN::FC::Service"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::FC::Service")
	not helpers.has_property(resource, "VpcConfig")
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "VpcConfig"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
