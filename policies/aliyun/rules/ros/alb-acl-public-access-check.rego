package infraguard.rules.aliyun.alb_acl_public_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "alb-acl-public-access-check",
	"severity": "high",
	"name": {
		"en": "ALB ACL Does Not Allow Public Access",
		"zh": "ALB 访问控制列表不允许配置所有地址段",
		"ja": "ALB ACL がパブリックアクセスを許可していない",
		"de": "ALB ACL erlaubt keinen öffentlichen Zugriff",
		"es": "La ACL ALB No Permite Acceso Público",
		"fr": "L'ACL ALB N'autorise Pas l'Accès Public",
		"pt": "A ACL ALB Não Permite Acesso Público"
	},
	"description": {
		"en": "Ensures that ALB access control lists do not contain 0.0.0.0/0 (allowing all IPs).",
		"zh": "确保 ALB 访问控制列表不包含 0.0.0.0/0（允许所有 IP）。",
		"ja": "ALB アクセス制御リストに 0.0.0.0/0（すべての IP を許可）が含まれていないことを確認します。",
		"de": "Stellt sicher, dass ALB-Zugriffssteuerungslisten 0.0.0.0/0 (Erlaubnis aller IPs) nicht enthalten.",
		"es": "Garantiza que las listas de control de acceso ALB no contengan 0.0.0.0/0 (permitiendo todas las IPs).",
		"fr": "Garantit que les listes de contrôle d'accès ALB ne contiennent pas 0.0.0.0/0 (autorisant toutes les IP).",
		"pt": "Garante que as listas de controle de acesso ALB não contenham 0.0.0.0/0 (permitindo todos os IPs)."
	},
	"reason": {
		"en": "Setting the ACL to 0.0.0.0/0 allows any IP to access the load balancer, significantly increasing security risks.",
		"zh": "将 ACL 设置为 0.0.0.0/0 允许任何 IP 访问负载均衡器，大大增加了安全风险。",
		"ja": "ACL を 0.0.0.0/0 に設定すると、任意の IP がロードバランサーにアクセスできるようになり、セキュリティリスクが大幅に増加します。",
		"de": "Das Setzen der ACL auf 0.0.0.0/0 erlaubt jeder IP den Zugriff auf den Load Balancer, was die Sicherheitsrisiken erheblich erhöht.",
		"es": "Establecer la ACL en 0.0.0.0/0 permite que cualquier IP acceda al equilibrador de carga, aumentando significativamente los riesgos de seguridad.",
		"fr": "Définir l'ACL sur 0.0.0.0/0 permet à n'importe quelle IP d'accéder à l'équilibreur de charge, augmentant considérablement les risques de sécurité.",
		"pt": "Definir a ACL como 0.0.0.0/0 permite que qualquer IP acesse o balanceador de carga, aumentando significativamente os riscos de segurança."
	},
	"recommendation": {
		"en": "Restrict the ACL to specific IP ranges instead of allowing all IPs.",
		"zh": "将 ACL 限制为特定的 IP 范围，而不是允许所有 IP。",
		"ja": "すべての IP を許可するのではなく、ACL を特定の IP 範囲に制限します。",
		"de": "Beschränken Sie die ACL auf spezifische IP-Bereiche, anstatt alle IPs zuzulassen.",
		"es": "Restrinja la ACL a rangos de IP específicos en lugar de permitir todas las IPs.",
		"fr": "Restreignez l'ACL à des plages d'IP spécifiques au lieu d'autoriser toutes les IP.",
		"pt": "Restrinja a ACL a intervalos de IP específicos em vez de permitir todos os IPs."
	},
	"resource_types": ["ALIYUN::ALB::Acl"]
}

# Check if ACL contains 0.0.0.0/0
contains_public_cidr(acl_resource) if {
	acl_entries := helpers.get_property(acl_resource, "AclEntries", [])
	some entry in acl_entries
	cidr := entry.Entry
	cidr == "0.0.0.0/0"
}

contains_public_cidr(acl_resource) if {
	acl_entries := helpers.get_property(acl_resource, "AclEntries", [])
	some entry in acl_entries
	cidr := entry.Entry
	cidr == "0.0.0.0"
}

is_compliant(resource) if {
	not contains_public_cidr(resource)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::Acl")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AclEntries"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
