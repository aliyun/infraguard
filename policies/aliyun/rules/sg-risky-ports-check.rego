package infraguard.rules.aliyun.sg_risky_ports_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "sg-risky-ports-check",
	"name": {
		"en": "Security group does not open risky ports to 0.0.0.0/0",
		"zh": "安全组不允许对全部网段开启风险端口",
		"ja": "セキュリティグループが 0.0.0.0/0 にリスクポートを開かない",
		"de": "Sicherheitsgruppe öffnet keine riskanten Ports für 0.0.0.0/0",
		"es": "El Grupo de Seguridad No Abre Puertos de Riesgo a 0.0.0.0/0",
		"fr": "Le Groupe de Sécurité N'ouvre Pas de Ports à Risque à 0.0.0.0/0",
		"pt": "Grupo de Segurança Não Abre Portas de Risco para 0.0.0.0/0",
	},
	"description": {
		"en": "When security group ingress rule source is set to 0.0.0.0/0, the port range should not include specified risky ports, considered compliant. If source is not 0.0.0.0/0, it's compliant even if risky ports are included.",
		"zh": "当安全组入网网段设置为 0.0.0.0/0 时，端口范围不包含指定风险端口，视为合规。若入网网段未设置为 0.0.0.0/0 时，即使端口范围包含指定的风险端口，也视为合规。",
		"ja": "セキュリティグループのイングレスルールのソースが 0.0.0.0/0 に設定されている場合、ポート範囲に指定されたリスクポートが含まれていない場合、準拠と見なされます。ソースが 0.0.0.0/0 でない場合、ポート範囲に指定されたリスクポートが含まれていても準拠と見なされます。",
		"de": "Wenn die Quelle der Sicherheitsgruppen-Eingangsregel auf 0.0.0.0/0 gesetzt ist, sollte der Portbereich keine angegebenen riskanten Ports enthalten, was als konform gilt. Wenn die Quelle nicht 0.0.0.0/0 ist, ist es konform, auch wenn riskante Ports enthalten sind.",
		"es": "Cuando la fuente de la regla de entrada del grupo de seguridad se establece en 0.0.0.0/0, el rango de puertos no debe incluir puertos de riesgo especificados, considerado conforme. Si la fuente no es 0.0.0.0/0, es conforme incluso si se incluyen puertos de riesgo.",
		"fr": "Lorsque la source de la règle d'entrée du groupe de sécurité est définie sur 0.0.0.0/0, la plage de ports ne doit pas inclure de ports à risque spécifiés, considéré comme conforme. Si la source n'est pas 0.0.0.0/0, c'est conforme même si des ports à risque sont inclus.",
		"pt": "Quando a origem da regra de entrada do grupo de segurança é definida como 0.0.0.0/0, o intervalo de portas não deve incluir portas de risco especificadas, considerado conforme. Se a origem não for 0.0.0.0/0, é conforme mesmo que portas de risco sejam incluídas.",
	},
	"severity": "high",
	"resource_types": ["ALIYUN::ECS::SecurityGroup"],
	"reason": {
		"en": "Security group opens risky ports to all IP addresses (0.0.0.0/0)",
		"zh": "安全组向所有 IP 地址(0.0.0.0/0)开放了风险端口",
		"ja": "セキュリティグループがすべての IP アドレス（0.0.0.0/0）にリスクポートを開いています",
		"de": "Sicherheitsgruppe öffnet riskante Ports für alle IP-Adressen (0.0.0.0/0)",
		"es": "El grupo de seguridad abre puertos de riesgo a todas las direcciones IP (0.0.0.0/0)",
		"fr": "Le groupe de sécurité ouvre des ports à risque à toutes les adresses IP (0.0.0.0/0)",
		"pt": "O grupo de segurança abre portas de risco para todos os endereços IP (0.0.0.0/0)",
	},
	"recommendation": {
		"en": "Remove risky port rules from security group ingress rules or restrict source IP range",
		"zh": "从安全组入站规则中删除风险端口规则，或限制源 IP 范围",
		"ja": "セキュリティグループのイングレスルールからリスクポートルールを削除するか、ソース IP 範囲を制限します",
		"de": "Entfernen Sie riskante Portregeln aus den Sicherheitsgruppen-Eingangsregeln oder beschränken Sie den Quell-IP-Bereich",
		"es": "Elimine las reglas de puertos de riesgo de las reglas de entrada del grupo de seguridad o restrinja el rango de IP de origen",
		"fr": "Supprimez les règles de ports à risque des règles d'entrée du groupe de sécurité ou restreignez la plage d'IP source",
		"pt": "Remova as regras de portas de risco das regras de entrada do grupo de segurança ou restrinja o intervalo de IP de origem",
	},
}

# Risky port ranges to check (common sensitive ports)
# Format: port ranges like "22/22", "3389/3389", "0/65535"
is_risky_port(port_range) if {
	# Common risky ports: SSH (22), RDP (3389), Telnet (23), MySQL (3306), etc.
	port_range in [
		"22/22",
		"23/23",
		"3389/3389",
		"3306/3306",
		"1433/1433",
		"5432/5432",
		"27017/27017",
		"6379/6379",
		"0/65535",
	]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ECS::SecurityGroup")

	# Get ingress rules
	ingress_rules := helpers.get_property(resource, "SecurityGroupIngress", [])

	# Check each rule
	some rule in ingress_rules
	source_cidr := object.get(rule, "SourceCidrIp", "")
	port_range := object.get(rule, "PortRange", "")

	# Only flag if source is 0.0.0.0/0 and port is risky
	source_cidr == "0.0.0.0/0"
	is_risky_port(port_range)

	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIngress", "SourceCidrIp"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
