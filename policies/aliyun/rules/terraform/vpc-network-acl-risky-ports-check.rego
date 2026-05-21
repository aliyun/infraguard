package infraguard.rules.terraform.vpc_network_acl_risky_ports_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "vpc-network-acl-risky-ports-check",
	"severity": "high",
	"name": {
		"en": "VPC Network ACL Risky Ports Check",
		"zh": "VPC 网络 ACL 禁用高风险端口",
		"ja": "VPC ネットワーク ACL リスクポートチェック",
		"de": "VPC-Netzwerk-ACL Risikoport-Prüfung",
		"es": "Verificación de Puertos de Riesgo de ACL de Red VPC",
		"fr": "Vérification des Ports à Risque de l'ACL Réseau VPC",
		"pt": "Verificação de Portas de Risco da ACL de Rede VPC"
	},
	"description": {
		"en": "Ensures VPC Network ACLs do not allow unrestricted access to risky ports (22, 3389).",
		"zh": "确保 VPC 网络 ACL 不允许对风险端口（22, 3389）的无限制访问。",
		"ja": "VPC ネットワーク ACL がリスクポート（22、3389）への無制限アクセスを許可しないことを確認します。",
		"de": "Stellt sicher, dass VPC-Netzwerk-ACLs keinen uneingeschränkten Zugriff auf riskante Ports (22, 3389) erlauben.",
		"es": "Garantiza que las ACL de red VPC no permitan acceso sin restricciones a puertos de riesgo (22, 3389).",
		"fr": "Garantit que les ACL réseau VPC n'autorisent pas l'accès sans restriction aux ports à risque (22, 3389).",
		"pt": "Garante que as ACLs de rede VPC não permitam acesso irrestrito a portas de risco (22, 3389)."
	},
	"reason": {
		"en": "Opening management ports to all IPs (0.0.0.0/0) creates a significant security risk.",
		"zh": "向所有 IP（0.0.0.0/0）开放管理端口会造成重大的安全风险。",
		"ja": "すべての IP（0.0.0.0/0）に管理ポートを開くことは、重大なセキュリティリスクを生み出します。",
		"de": "Das Öffnen von Verwaltungsports für alle IPs (0.0.0.0/0) schafft ein erhebliches Sicherheitsrisiko.",
		"es": "Abrir puertos de gestión a todas las IPs (0.0.0.0/0) crea un riesgo de seguridad significativo.",
		"fr": "L'ouverture des ports de gestion à toutes les IP (0.0.0.0/0) crée un risque de sécurité important.",
		"pt": "Abrir portas de gerenciamento para todos os IPs (0.0.0.0/0) cria um risco de segurança significativo."
	},
	"recommendation": {
		"en": "Restrict source_cidr_ip in ingress_acl_entries to specific trusted IP ranges for ports 22 and 3389.",
		"zh": "将 ingress_acl_entries 中的 source_cidr_ip 限制为特定的可信 IP 范围（针对端口 22 和 3389）。",
		"ja": "ポート 22 と 3389 の ingress_acl_entries の source_cidr_ip を特定の信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie source_cidr_ip in ingress_acl_entries auf spezifische vertrauenswürdige IP-Bereiche für Ports 22 und 3389.",
		"es": "Restrinja source_cidr_ip en ingress_acl_entries a rangos de IP de confianza específicos para los puertos 22 y 3389.",
		"fr": "Restreignez source_cidr_ip dans ingress_acl_entries à des plages d'IP de confiance spécifiques pour les ports 22 et 3389.",
		"pt": "Restrinja source_cidr_ip em ingress_acl_entries a intervalos de IP confiáveis específicos para as portas 22 e 3389."
	},
	"resource_types": ["alicloud_network_acl"],
	"iac_type": "terraform"
}

risky_ports := [22, 3389]

is_public_cidr(cidr) if {
	cidr == "0.0.0.0/0"
}

is_public_cidr(cidr) if {
	cidr == "::/0"
}

port_is_risky(port, _) if {
	port == "-1/-1"
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

# Normalize entries to always be a list (single block is stored as a map)
normalize_entries(val) := [val] if {
	is_object(val)
}

normalize_entries(val) := val if {
	is_array(val)
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_network_acl")
	raw_entries := tf.get_attribute(resource, "ingress_acl_entries", [])
	entries := normalize_entries(raw_entries)
	some entry in entries
	entry.policy == "accept"
	is_public_cidr(entry.source_cidr_ip)
	port_is_risky(entry.port, risky_ports)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_network_acl.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
