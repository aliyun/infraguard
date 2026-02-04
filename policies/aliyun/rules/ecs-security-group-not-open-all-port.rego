package infraguard.rules.aliyun.ecs_security_group_not_open_all_port

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-not-open-all-port",
	"name": {
		"en": "Security Group Ingress Not Open All Ports",
		"zh": "安全组入网设置中不能有对所有端口开放的访问规则",
		"ja": "セキュリティグループイングレスがすべてのポートを開放していない",
		"de": "Sicherheitsgruppe Ingress öffnet nicht alle Ports",
		"es": "Ingress de Grupo de Seguridad No Abre Todos los Puertos",
		"fr": "Ingress du Groupe de Sécurité N'Ouvre Pas Tous les Ports",
		"pt": "Ingress de Grupo de Segurança Não Abre Todas as Portas",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules should not allow all ports. When the port range is not set to -1/-1, it is considered compliant.",
		"zh": "安全组入方向授权策略为允许，当端口范围未设置为-1/-1 时，视为合规。如果端口范围设置为-1/-1，但被优先级更高的授权策略拒绝，视为合规。",
		"ja": "セキュリティグループのイングレスルールはすべてのポートを許可すべきではありません。ポート範囲が -1/-1 に設定されていない場合、準拠と見なされます。",
		"de": "Sicherheitsgruppen-Ingress-Regeln sollten nicht alle Ports erlauben. Wenn der Portbereich nicht auf -1/-1 gesetzt ist, wird dies als konform betrachtet.",
		"es": "Las reglas de ingreso del grupo de seguridad no deben permitir todos los puertos. Cuando el rango de puertos no está establecido en -1/-1, se considera conforme.",
		"fr": "Les règles d'ingress du groupe de sécurité ne doivent pas autoriser tous les ports. Lorsque la plage de ports n'est pas définie sur -1/-1, elle est considérée comme conforme.",
		"pt": "As regras de ingresso do grupo de segurança não devem permitir todas as portas. Quando o intervalo de portas não está definido como -1/-1, é considerado conforme.",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows all ports (PortRange=-1/-1), which poses a security risk by allowing access to any port.",
		"zh": "安全组有一条入网规则允许所有端口（PortRange=-1/-1），允许访问任何端口，存在安全风险。",
		"ja": "セキュリティグループにすべてのポート（PortRange=-1/-1）を許可するイングレスルールがあり、任意のポートへのアクセスを許可することでセキュリティリスクをもたらします。",
		"de": "Die Sicherheitsgruppe hat eine Ingress-Regel, die alle Ports (PortRange=-1/-1) erlaubt, was ein Sicherheitsrisiko darstellt, indem sie Zugriff auf jeden Port ermöglicht.",
		"es": "El grupo de seguridad tiene una regla de ingreso que permite todos los puertos (PortRange=-1/-1), lo que plantea un riesgo de seguridad al permitir el acceso a cualquier puerto.",
		"fr": "Le groupe de sécurité a une règle d'ingress qui autorise tous les ports (PortRange=-1/-1), ce qui pose un risque de sécurité en autorisant l'accès à n'importe quel port.",
		"pt": "O grupo de segurança tem uma regra de ingresso que permite todas as portas (PortRange=-1/-1), o que representa um risco de segurança ao permitir acesso a qualquer porta.",
	},
	"recommendation": {
		"en": "Restrict ingress rules to specific port ranges based on actual business requirements instead of using '-1/-1' (all ports).",
		"zh": "根据实际业务需求，将入网规则限制为特定的端口范围，而不是使用'-1/-1'（所有端口）。",
		"ja": "実際のビジネス要件に基づいて、'-1/-1'（すべてのポート）を使用するのではなく、イングレスルールを特定のポート範囲に制限します。",
		"de": "Beschränken Sie Ingress-Regeln auf spezifische Portbereiche basierend auf tatsächlichen Geschäftsanforderungen, anstatt '-1/-1' (alle Ports) zu verwenden.",
		"es": "Restrinja las reglas de ingreso a rangos de puertos específicos según los requisitos comerciales reales en lugar de usar '-1/-1' (todos los puertos).",
		"fr": "Restreignez les règles d'ingress à des plages de ports spécifiques en fonction des exigences commerciales réelles au lieu d'utiliser '-1/-1' (tous les ports).",
		"pt": "Restrinja as regras de ingresso a intervalos de portas específicos com base nos requisitos comerciais reais em vez de usar '-1/-1' (todas as portas).",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if an ingress rule allows all ports with accept policy
is_all_port_accept(rule) if {
	rule.PortRange == "-1/-1"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_all_port_accept(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10), "PortRange"],
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
	is_all_port_accept(props)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "PortRange"],
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
	is_all_port_accept(perm)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10), "PortRange"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
