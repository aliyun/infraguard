# Network and Data Security Best Practice Pack
# Best practices for network and data security including encryption, access control, and secure configurations.
package infraguard.packs.aliyun.network_data_security_best_practice

import rego.v1

# Pack metadata with i18n support
pack_meta := {
	"id": "network-data-security-best-practice",
	"name": {
		"en": "Network and Data Security Best Practice",
		"zh": "网络及数据安全最佳实践",
		"ja": "ネットワークおよびデータセキュリティのベストプラクティス",
		"de": "Netzwerk- und Datensicherheit Best Practices",
		"es": "Mejores Prácticas de Seguridad de Red y Datos",
		"fr": "Meilleures Pratiques de Sécurité Réseau et Données",
		"pt": "Melhores Práticas de Segurança de Rede e Dados"
	},
	"description": {
		"en": "Best practices for network and data security including ECS instance security, OSS bucket encryption and access control, RDS instance security configurations.",
		"zh": "网络及数据安全最佳实践，包括 ECS 实例安全、OSS 存储空间加密和访问控制、RDS 实例安全配置。",
		"ja": "ECS インスタンスセキュリティ、OSS バケットの暗号化とアクセス制御、RDS インスタンスのセキュリティ設定を含む、ネットワークおよびデータセキュリティのベストプラクティス。",
		"de": "Best Practices für Netzwerk- und Datensicherheit, einschließlich ECS-Instanz-Sicherheit, OSS-Bucket-Verschlüsselung und Zugriffskontrolle, RDS-Instanz-Sicherheitskonfigurationen.",
		"es": "Mejores prácticas para la seguridad de red y datos, incluyendo seguridad de instancias ECS, cifrado y control de acceso de buckets OSS, configuraciones de seguridad de instancias RDS.",
		"fr": "Meilleures pratiques pour la sécurité réseau et des données, incluant la sécurité des instances ECS, le chiffrement et le contrôle d'accès des buckets OSS, les configurations de sécurité des instances RDS.",
		"pt": "Melhores práticas para segurança de rede e dados, incluindo segurança de instâncias ECS, criptografia e controle de acesso de buckets OSS, configurações de segurança de instâncias RDS."
	},
	"rules": [
		"ecs-in-use-disk-encrypted",
		"ecs-instances-in-vpc",
		"oss-bucket-logging-enabled",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-server-side-encryption-enabled",
		"oss-encryption-byok-check",
		"rds-public-access-check"
	]
}
