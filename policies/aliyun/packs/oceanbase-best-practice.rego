package infraguard.packs.aliyun.oceanbase_best_practice

import rego.v1

pack_meta := {
	"id": "oceanbase-best-practice",
	"name": {
		"en": "OceanBase Best Practice",
		"zh": "OceanBase 最佳实践",
		"ja": "OceanBase のベストプラクティス",
		"de": "OceanBase Best Practices",
		"es": "Mejores Prácticas de OceanBase",
		"fr": "Meilleures Pratiques OceanBase",
		"pt": "Melhores Práticas do OceanBase",
	},
	"description": {
		"en": "Continuously check OceanBase compliance based on security practices.",
		"zh": "基于安全实践持续检查 OceanBase 的合规性。",
		"ja": "セキュリティ実践に基づいて OceanBase のコンプライアンスを継続的にチェックします。",
		"de": "Kontinuierliche Überprüfung der OceanBase-Compliance basierend auf Sicherheitspraktiken.",
		"es": "Verificar continuamente el cumplimiento de OceanBase basándose en prácticas de seguridad.",
		"fr": "Vérifier continuellement la conformité d'OceanBase sur la base des pratiques de sécurité.",
		"pt": "Verificar continuamente a conformidade do OceanBase com base em práticas de segurança.",
	},
	"rules": [],
	# "oceanbase-instance-enabled-backup",  # Commented: ROS does not support ALIYUN::OceanBase::DBInstance resource type
	# "oceanbase-instance-enabled-ssl",
	# "oceanbase-instance-enabled-sql-diagnosis",
	# "oceanbase-tenant-security-ip-check",
	# "oceanbase-tenant-enabled-encryption",

}
