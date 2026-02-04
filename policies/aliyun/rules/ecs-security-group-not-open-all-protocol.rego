package infraguard.rules.aliyun.ecs_security_group_not_open_all_protocol

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "ecs-security-group-not-open-all-protocol",
	"name": {
		"en": "Security Group Ingress Not Open All Protocols",
		"zh": "安全组入网设置不能有对所有协议开放的访问规则",
		"ja": "セキュリティグループイングレスがすべてのプロトコルを開放していない",
		"de": "Sicherheitsgruppe Ingress öffnet nicht alle Protokolle",
		"es": "Ingress de Grupo de Seguridad No Abre Todos los Protocolos",
		"fr": "Ingress du Groupe de Sécurité N'Ouvre Pas Tous les Protocoles",
		"pt": "Ingress de Grupo de Segurança Não Abre Todos os Protocolos",
	},
	"severity": "high",
	"description": {
		"en": "Security group ingress rules should not allow all protocols. When the protocol type is not set to ALL, it is considered compliant.",
		"zh": "安全组入方向授权策略为允许，当协议类型未设置为 ALL 时，视为合规。如果协议类型设置为 ALL，但被优先级更高的授权策略拒绝，视为合规。",
		"ja": "セキュリティグループのイングレスルールはすべてのプロトコルを許可すべきではありません。プロトコルタイプが ALL に設定されていない場合、準拠と見なされます。",
		"de": "Sicherheitsgruppen-Ingress-Regeln sollten nicht alle Protokolle erlauben. Wenn der Protokolltyp nicht auf ALL gesetzt ist, wird dies als konform betrachtet.",
		"es": "Las reglas de ingreso del grupo de seguridad no deben permitir todos los protocolos. Cuando el tipo de protocolo no está establecido en ALL, se considera conforme.",
		"fr": "Les règles d'ingress du groupe de sécurité ne doivent pas autoriser tous les protocoles. Lorsque le type de protocole n'est pas défini sur ALL, il est considéré comme conforme.",
		"pt": "As regras de ingresso do grupo de segurança não devem permitir todos os protocolos. Quando o tipo de protocolo não está definido como ALL, é considerado conforme.",
	},
	"reason": {
		"en": "The security group has an ingress rule that allows all protocols (IpProtocol=all), which poses a security risk by allowing any type of network traffic.",
		"zh": "安全组有一条入网规则允许所有协议（IpProtocol=all），允许任何类型的网络流量，存在安全风险。",
		"ja": "セキュリティグループにすべてのプロトコル（IpProtocol=all）を許可するイングレスルールがあり、あらゆるタイプのネットワークトラフィックを許可することでセキュリティリスクをもたらします。",
		"de": "Die Sicherheitsgruppe hat eine Ingress-Regel, die alle Protokolle (IpProtocol=all) erlaubt, was ein Sicherheitsrisiko darstellt, indem sie jeden Typ von Netzwerkverkehr ermöglicht.",
		"es": "El grupo de seguridad tiene una regla de ingreso que permite todos los protocolos (IpProtocol=all), lo que plantea un riesgo de seguridad al permitir cualquier tipo de tráfico de red.",
		"fr": "Le groupe de sécurité a une règle d'ingress qui autorise tous les protocoles (IpProtocol=all), ce qui pose un risque de sécurité en autorisant tout type de trafic réseau.",
		"pt": "O grupo de segurança tem uma regra de ingresso que permite todos os protocolos (IpProtocol=all), o que representa um risco de segurança ao permitir qualquer tipo de tráfego de rede.",
	},
	"recommendation": {
		"en": "Restrict ingress rules to specific protocols (tcp, udp, icmp) based on actual business requirements instead of using 'all'.",
		"zh": "根据实际业务需求，将入网规则限制为特定的协议（tcp、udp、icmp），而不是使用'all'。",
		"ja": "実際のビジネス要件に基づいて、'all' を使用するのではなく、イングレスルールを特定のプロトコル（tcp、udp、icmp）に制限します。",
		"de": "Beschränken Sie Ingress-Regeln auf spezifische Protokolle (tcp, udp, icmp) basierend auf tatsächlichen Geschäftsanforderungen, anstatt 'all' zu verwenden.",
		"es": "Restrinja las reglas de ingreso a protocolos específicos (tcp, udp, icmp) según los requisitos comerciales reales en lugar de usar 'all'.",
		"fr": "Restreignez les règles d'ingress à des protocoles spécifiques (tcp, udp, icmp) en fonction des exigences commerciales réelles au lieu d'utiliser 'all'.",
		"pt": "Restrinja as regras de ingresso a protocolos específicos (tcp, udp, icmp) com base nos requisitos comerciais reais em vez de usar 'all'.",
	},
	"resource_types": ["ALIYUN::ECS::SecurityGroup", "ALIYUN::ECS::SecurityGroupIngress", "ALIYUN::ECS::SecurityGroupIngresses"],
}

# Check if an ingress rule allows all protocols with accept policy
is_all_protocol_accept(rule) if {
	rule.IpProtocol == "all"
	object.get(rule, "Policy", "accept") == "accept"
}

# Check SecurityGroup resource for ingress rules
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")
	some i, rule in resource.Properties.SecurityGroupIngress
	is_all_protocol_accept(rule)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", format_int(i, 10), "IpProtocol"],
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
	is_all_protocol_accept(props)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "IpProtocol"],
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
	is_all_protocol_accept(perm)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Permissions", format_int(i, 10), "IpProtocol"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
