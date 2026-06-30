package infraguard.packs.aliyun.oss_compliance_management_best_practice

import rego.v1

pack_meta := {
	"id": "oss-compliance-management-best-practice",
	"name": {
		"en": "OSS Compliance Management Best Practice",
		"zh": "OSS 合规管理最佳实践",
		"ja": "OSS コンプライアンス管理のベストプラクティス",
		"de": "OSS-Compliance-Management Best Practices",
		"es": "Mejores Prácticas de Gestión de Cumplimiento de OSS",
		"fr": "Meilleures Pratiques de Gestion de la Conformité OSS",
		"pt": "Melhores Práticas de Gestão de Conformidade OSS"
	},
	"description": {
		"en": "Best practices for OSS bucket compliance management, covering access control, encryption, logging, versioning, and security policies.",
		"zh": "OSS 存储空间合规管理最佳实践,涵盖访问控制、加密、日志、版本控制和安全策略。",
		"ja": "アクセス制御、暗号化、ログ、バージョン管理、セキュリティポリシーをカバーする OSS バケットコンプライアンス管理のベストプラクティス。",
		"de": "Best Practices für das OSS-Bucket-Compliance-Management, einschließlich Zugriffskontrolle, Verschlüsselung, Protokollierung, Versionskontrolle und Sicherheitsrichtlinien.",
		"es": "Mejores prácticas para la gestión de cumplimiento de buckets OSS, que cubre control de acceso, cifrado, registro, control de versiones y políticas de seguridad.",
		"fr": "Meilleures pratiques pour la gestion de la conformité des buckets OSS, couvrant le contrôle d'accès, le chiffrement, l'enregistrement, le contrôle de version et les politiques de sécurité.",
		"pt": "Melhores práticas para gestão de conformidade de buckets OSS, cobrindo controle de acesso, criptografia, registro, controle de versão e políticas de segurança."
	},
	"rules": [
		"oss-bucket-logging-enabled",
		"oss-bucket-policy-no-any-anonymous",
		"oss-bucket-policy-outside-organization-check",
		"oss-bucket-public-read-prohibited",
		"oss-bucket-public-write-prohibited",
		"oss-bucket-referer-limit",
		"oss-bucket-server-side-encryption-enabled",
		"oss-bucket-versioning-enabled",
		"oss-zrs-enabled"
	]
}
