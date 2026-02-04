package infraguard.rules.aliyun.vpc_network_acl_risky_ports_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "vpc-network-acl-risky-ports-check",
	"name": {
		"en": "VPC Network ACL Risky Ports Check",
		"zh": "VPC 网络 ACL 禁用高风险端口",
		"ja": "VPC ネットワーク ACL リスクポートチェック",
		"de": "VPC-Netzwerk-ACL Risikoport-Prüfung",
		"es": "Verificación de Puertos de Riesgo de ACL de Red VPC",
		"fr": "Vérification des Ports à Risque de l'ACL Réseau VPC",
		"pt": "Verificação de Portas de Risco da ACL de Rede VPC",
	},
	"severity": "high",
	"description": {
		"en": "Ensures VPC Network ACLs do not allow unrestricted access to risky ports (22, 3389).",
		"zh": "确保 VPC 网络 ACL 不允许对风险端口（22, 3389）的无限制访问。",
		"ja": "VPC ネットワーク ACL がリスクポート（22、3389）への無制限アクセスを許可しないことを確認します。",
		"de": "Stellt sicher, dass VPC-Netzwerk-ACLs keinen uneingeschränkten Zugriff auf riskante Ports (22, 3389) erlauben.",
		"es": "Garantiza que las ACL de red VPC no permitan acceso sin restricciones a puertos de riesgo (22, 3389).",
		"fr": "Garantit que les ACL réseau VPC n'autorisent pas l'accès sans restriction aux ports à risque (22, 3389).",
		"pt": "Garante que as ACLs de rede VPC não permitam acesso irrestrito a portas de risco (22, 3389).",
	},
	"reason": {
		"en": "Opening management ports to all IPs (0.0.0.0/0) creates a significant security risk.",
		"zh": "向所有 IP（0.0.0.0/0）开放管理端口会造成重大的安全风险。",
		"ja": "すべての IP（0.0.0.0/0）に管理ポートを開くことは、重大なセキュリティリスクを生み出します。",
		"de": "Das Öffnen von Verwaltungsports für alle IPs (0.0.0.0/0) schafft ein erhebliches Sicherheitsrisiko.",
		"es": "Abrir puertos de gestión a todas las IPs (0.0.0.0/0) crea un riesgo de seguridad significativo.",
		"fr": "L'ouverture des ports de gestion à toutes les IP (0.0.0.0/0) crée un risque de sécurité important.",
		"pt": "Abrir portas de gerenciamento para todos os IPs (0.0.0.0/0) cria um risco de segurança significativo.",
	},
	"recommendation": {
		"en": "Restrict access to ports 22 and 3389 to specific trusted IP ranges.",
		"zh": "将对 22 和 3389 端口的访问限制在特定的可信 IP 范围内。",
		"ja": "ポート 22 と 3389 へのアクセスを特定の信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie den Zugriff auf die Ports 22 und 3389 auf spezifische vertrauenswürdige IP-Bereiche.",
		"es": "Restrinja el acceso a los puertos 22 y 3389 a rangos de IP específicos de confianza.",
		"fr": "Restreignez l'accès aux ports 22 et 3389 à des plages d'IP spécifiques de confiance.",
		"pt": "Restrinja o acesso às portas 22 e 3389 a intervalos de IP específicos confiáveis.",
	},
	"resource_types": ["ALIYUN::VPC::NetworkAcl"],
}

risky_ports := [22, 3389]

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::VPC::NetworkAcl")
	entries := helpers.get_property(resource, "IngressAclEntries", [])
	some entry in entries
	entry.Policy == "accept"
	helpers.is_public_cidr(entry.SourceCidrIp)
	port_is_risky(entry.Port, risky_ports)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IngressAclEntries"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}

port_is_risky(port, _) if {
	port == "all"
}

port_is_risky(port, target_ports) if {
	is_number(port)
	port in target_ports
}

port_is_risky(port, target_ports) if {
	is_string(port)
	parts := split(port, "/")
	count(parts) == 2
	start := to_number(parts[0])
	end := to_number(parts[1])
	some p in target_ports
	p >= start
	p <= end
}
