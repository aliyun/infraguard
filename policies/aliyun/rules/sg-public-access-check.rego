package infraguard.rules.aliyun.sg_public_access_check

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "sg-public-access-check",
	"name": {
		"en": "Security Group Ingress Valid",
		"zh": "安全组入网设置有效",
		"ja": "セキュリティグループイングレスが有効",
		"de": "Sicherheitsgruppe Ingress gültig",
		"es": "Ingress de Grupo de Seguridad Válido",
		"fr": "Ingress du Groupe de Sécurité Valide",
		"pt": "Ingress de Grupo de Segurança Válido",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules should not allow all ports (-1/-1) from all sources (0.0.0.0/0) simultaneously.",
		"zh": "安全组入方向授权策略为允许，当端口范围-1/-1 和授权对象 0.0.0.0/0 未同时出现，或者被优先级更高的授权策略拒绝，视为合规。",
		"ja": "セキュリティグループのイングレスルールは、すべてのソース（0.0.0.0/0）からすべてのポート（-1/-1）を同時に許可すべきではありません。",
		"de": "Sicherheitsgruppen-Ingress-Regeln sollten nicht gleichzeitig alle Ports (-1/-1) von allen Quellen (0.0.0.0/0) erlauben.",
		"es": "Las reglas de ingreso del grupo de seguridad no deben permitir todos los puertos (-1/-1) desde todas las fuentes (0.0.0.0/0) simultáneamente.",
		"fr": "Les règles d'ingress du groupe de sécurité ne doivent pas autoriser tous les ports (-1/-1) depuis toutes les sources (0.0.0.0/0) simultanément.",
		"pt": "As regras de ingresso do grupo de segurança não devem permitir todas as portas (-1/-1) de todas as fontes (0.0.0.0/0) simultaneamente.",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows all ports from all sources (0.0.0.0/0 with port range -1/-1), which poses a critical security risk.",
		"zh": "安全组有一条入网规则同时允许所有端口（-1/-1）和所有来源（0.0.0.0/0），存在严重安全风险。",
		"ja": "セキュリティグループに、すべてのソース（ポート範囲 -1/-1 の 0.0.0.0/0）からすべてのポートを許可するイングレスルールがあり、重大なセキュリティリスクをもたらします。",
		"de": "Die Sicherheitsgruppe hat eine Ingress-Regel, die alle Ports von allen Quellen (0.0.0.0/0 mit Portbereich -1/-1) erlaubt, was ein kritisches Sicherheitsrisiko darstellt.",
		"es": "El grupo de seguridad tiene una regla de ingreso que permite todos los puertos desde todas las fuentes (0.0.0.0/0 con rango de puertos -1/-1), lo que plantea un riesgo de seguridad crítico.",
		"fr": "Le groupe de sécurité a une règle d'ingress qui autorise tous les ports depuis toutes les sources (0.0.0.0/0 avec plage de ports -1/-1), ce qui pose un risque de sécurité critique.",
		"pt": "O grupo de segurança tem uma regra de ingresso que permite todas as portas de todas as fontes (0.0.0.0/0 com intervalo de portas -1/-1), o que representa um risco de segurança crítico.",
	},
	"recommendation": {
		"en": "Either restrict the source IP range to specific CIDR blocks or limit the port range to specific ports based on actual business requirements.",
		"zh": "根据实际业务需求，将来源 IP 范围限制为特定的 CIDR 块，或将端口范围限制为特定的端口。",
		"ja": "実際のビジネス要件に基づいて、ソース IP 範囲を特定の CIDR ブロックに制限するか、ポート範囲を特定のポートに制限します。",
		"de": "Beschränken Sie entweder den Quell-IP-Bereich auf spezifische CIDR-Blöcke oder begrenzen Sie den Portbereich auf spezifische Ports basierend auf tatsächlichen Geschäftsanforderungen.",
		"es": "Restrinja el rango de IP de origen a bloques CIDR específicos o limite el rango de puertos a puertos específicos según los requisitos comerciales reales.",
		"fr": "Restreignez soit la plage d'IP source à des blocs CIDR spécifiques, soit limitez la plage de ports à des ports spécifiques en fonction des exigences commerciales réelles.",
		"pt": "Restrinja o intervalo de IP de origem a blocos CIDR específicos ou limite o intervalo de portas a portas específicas com base nos requisitos comerciais reais.",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if an ingress rule is a public access rule (all ports from all sources)
is_public_access(rule) if {
	rule.PortRange == "-1/-1"
	rule.SourceCidrIp == "0.0.0.0/0"
	object.get(rule, "Policy", "accept") == "accept"
}

is_public_access(rule) if {
	rule.PortRange == "-1/-1"
	rule.Ipv6SourceCidrIp == "::/0"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_public_access(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10)],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

# Check SecurityGroupIngress resource
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroupIngress")
	props := resource.Properties
	ingress_rule := {
		"PortRange": props.PortRange,
		"SourceCidrIp": object.get(props, "SourceCidrIp", ""),
		"Ipv6SourceCidrIp": object.get(props, "Ipv6SourceCidrIp", ""),
		"Policy": object.get(props, "Policy", "accept"),
	}
	is_public_access(ingress_rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

# Check SecurityGroupIngresses resource
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroupIngresses")
	some i, perm in resource.Properties.Permissions
	ingress_rule := {
		"PortRange": perm.PortRange,
		"SourceCidrIp": object.get(perm, "SourceCidrIp", ""),
		"Ipv6SourceCidrIp": object.get(perm, "Ipv6SourceCidrIp", ""),
		"Policy": object.get(perm, "Policy", "accept"),
	}
	is_public_access(ingress_rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10)],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
