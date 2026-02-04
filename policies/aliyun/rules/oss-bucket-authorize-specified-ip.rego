package infraguard.rules.aliyun.oss_bucket_authorize_specified_ip

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "oss-bucket-authorize-specified-ip",
	"name": {
		"en": "OSS Bucket Authorize Specified IP",
		"zh": "OSS 存储桶策略授权特定 IP",
		"ja": "OSS バケットが指定 IP を承認",
		"de": "OSS-Bucket autorisiert angegebene IP",
		"es": "Bucket OSS Autoriza IP Especificada",
		"fr": "Bucket OSS Autorise IP Spécifiée",
		"pt": "Bucket OSS Autoriza IP Especificada",
	},
	"severity": "medium",
	"description": {
		"en": "Ensures OSS bucket policies restrict access to specified IP ranges.",
		"zh": "确保 OSS 存储桶策略限制了特定 IP 范围的访问。",
		"ja": "OSS バケットポリシーが特定の IP 範囲へのアクセスを制限していることを確認します。",
		"de": "Stellt sicher, dass OSS-Bucket-Richtlinien den Zugriff auf angegebene IP-Bereiche einschränken.",
		"es": "Garantiza que las políticas de bucket OSS restrinjan el acceso a rangos de IP especificados.",
		"fr": "Garantit que les politiques de bucket OSS restreignent l'accès aux plages d'IP spécifiées.",
		"pt": "Garante que as políticas de bucket OSS restrinjam o acesso a intervalos de IP especificados.",
	},
	"reason": {
		"en": "Restricting access by IP helps prevent unauthorized access even if credentials are compromised.",
		"zh": "通过 IP 限制访问有助于防止在凭据泄露时发生未经授权的访问。",
		"ja": "IP によるアクセス制限は、認証情報が侵害された場合でも不正アクセスを防ぐのに役立ちます。",
		"de": "Die Einschränkung des Zugriffs nach IP hilft, unbefugten Zugriff zu verhindern, auch wenn Anmeldeinformationen kompromittiert sind.",
		"es": "Restringir el acceso por IP ayuda a prevenir el acceso no autorizado incluso si las credenciales están comprometidas.",
		"fr": "Restreindre l'accès par IP aide à prévenir l'accès non autorisé même si les identifiants sont compromis.",
		"pt": "Restringir o acesso por IP ajuda a prevenir acesso não autorizado mesmo se as credenciais estiverem comprometidas.",
	},
	"recommendation": {
		"en": "Add IP restriction conditions (acs:SourceIp) to the OSS bucket policy.",
		"zh": "在 OSS 存储桶策略中添加 IP 限制条件（acs:SourceIp）。",
		"ja": "OSS バケットポリシーに IP 制限条件（acs:SourceIp）を追加します。",
		"de": "Fügen Sie IP-Beschränkungsbedingungen (acs:SourceIp) zur OSS-Bucket-Richtlinie hinzu.",
		"es": "Agregue condiciones de restricción de IP (acs:SourceIp) a la política de bucket OSS.",
		"fr": "Ajoutez des conditions de restriction IP (acs:SourceIp) à la politique de bucket OSS.",
		"pt": "Adicione condições de restrição de IP (acs:SourceIp) à política de bucket OSS.",
	},
	"resource_types": ["ALIYUN::OSS::Bucket"],
}

is_compliant(resource) if {
	policy := helpers.get_property(resource, "Policy", {})
	statements := object.get(policy, "Statement", [])
	some statement in statements
	condition := object.get(statement, "Condition", {})
	ip_address := object.get(condition, "IpAddress", {})

	# Check for acs:SourceIp in the IpAddress condition
	object.get(ip_address, "acs:SourceIp", null) != null
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OSS::Bucket")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Policy"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
