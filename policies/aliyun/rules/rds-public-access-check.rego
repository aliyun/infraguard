package infraguard.rules.aliyun.rds_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "rds-public-access-check",
	"severity": "high",
	"name": {
		"en": "RDS Instance Public Access Check",
		"zh": "RDS 实例不配置公网地址",
		"ja": "RDS インスタンスのパブリックアクセスチェック",
		"de": "RDS-Instanz öffentlicher Zugriff Prüfung",
		"es": "Verificación de Acceso Público de Instancia RDS",
		"fr": "Vérification d'Accès Public d'Instance RDS",
		"pt": "Verificação de Acesso Público de Instância RDS"
	},
	"description": {
		"en": "RDS instances should not be configured with public network addresses. Public access exposes databases to potential security threats from the internet.",
		"zh": "RDS 实例不应配置公网地址。公网访问会使数据库暴露于来自互联网的潜在安全威胁。",
		"ja": "RDS インスタンスはパブリックネットワークアドレスで設定すべきではありません。パブリックアクセスにより、データベースがインターネットからの潜在的なセキュリティ脅威にさらされます。",
		"de": "RDS-Instanzen sollten nicht mit öffentlichen Netzwerkadressen konfiguriert werden. Öffentlicher Zugriff setzt Datenbanken potenziellen Sicherheitsbedrohungen aus dem Internet aus.",
		"es": "Las instancias RDS no deben configurarse con direcciones de red públicas. El acceso público expone las bases de datos a posibles amenazas de seguridad de internet.",
		"fr": "Les instances RDS ne doivent pas être configurées avec des adresses réseau publiques. L'accès public expose les bases de données à des menaces de sécurité potentielles d'Internet.",
		"pt": "Instâncias RDS não devem ser configuradas com endereços de rede pública. O acesso público expõe bancos de dados a ameaças potenciais de segurança da internet."
	},
	"reason": {
		"en": "The RDS instance is configured with public network access, which exposes the database to security risks from the internet.",
		"zh": "RDS 实例配置了公网访问，使数据库暴露于来自互联网的安全风险。",
		"ja": "RDS インスタンスがパブリックネットワークアクセスで設定されているため、データベースがインターネットからのセキュリティリスクにさらされます。",
		"de": "Die RDS-Instanz ist mit öffentlichem Netzwerkzugriff konfiguriert, was die Datenbank Sicherheitsrisiken aus dem Internet aussetzt.",
		"es": "La instancia RDS está configurada con acceso a red pública, lo que expone la base de datos a riesgos de seguridad de internet.",
		"fr": "L'instance RDS est configurée avec un accès réseau public, ce qui expose la base de données aux risques de sécurité d'Internet.",
		"pt": "A instância RDS está configurada com acesso à rede pública, o que expõe o banco de dados a riscos de segurança da internet."
	},
	"recommendation": {
		"en": "Disable public network access for the RDS instance by setting AllocatePublicConnection to false or not configuring it.",
		"zh": "通过将 AllocatePublicConnection 设置为 false 或不配置该属性，禁用 RDS 实例的公网访问。",
		"ja": "AllocatePublicConnection を false に設定するか、設定しないことで、RDS インスタンスのパブリックネットワークアクセスを無効にします。",
		"de": "Deaktivieren Sie den öffentlichen Netzwerkzugriff für die RDS-Instanz, indem Sie AllocatePublicConnection auf false setzen oder es nicht konfigurieren.",
		"es": "Deshabilite el acceso a la red pública para la instancia RDS estableciendo AllocatePublicConnection en false o no configurándolo.",
		"fr": "Désactivez l'accès réseau public pour l'instance RDS en définissant AllocatePublicConnection sur false ou en ne le configurant pas.",
		"pt": "Desabilite o acesso à rede pública para a instância RDS definindo AllocatePublicConnection como false ou não configurando-o."
	},
	"resource_types": ["ALIYUN::RDS::DBInstance"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
	has_public_access(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AllocatePublicConnection"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

has_public_access(resource) if {
	resource.Properties.AllocatePublicConnection == true
}
