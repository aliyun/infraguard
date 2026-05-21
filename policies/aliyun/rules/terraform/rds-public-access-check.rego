package infraguard.rules.terraform.rds_public_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "Do not create alicloud_db_connection resources to avoid allocating public network addresses for RDS instances.",
		"zh": "不要创建 alicloud_db_connection 资源，以避免为 RDS 实例分配公网地址。",
		"ja": "RDS インスタンスにパブリックネットワークアドレスを割り当てないように、alicloud_db_connection リソースを作成しないでください。",
		"de": "Erstellen Sie keine alicloud_db_connection-Ressourcen, um die Zuweisung öffentlicher Netzwerkadressen für RDS-Instanzen zu vermeiden.",
		"es": "No cree recursos alicloud_db_connection para evitar asignar direcciones de red pública a instancias RDS.",
		"fr": "Ne créez pas de ressources alicloud_db_connection pour éviter d'attribuer des adresses réseau publiques aux instances RDS.",
		"pt": "Não crie recursos alicloud_db_connection para evitar a alocação de endereços de rede pública para instâncias RDS."
	},
	"resource_types": ["alicloud_db_connection"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_db_connection")
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_db_connection.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
