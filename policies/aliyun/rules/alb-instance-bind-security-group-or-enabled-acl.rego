package infraguard.rules.aliyun.alb_instance_bind_security_group_or_enabled_acl

import rego.v1

import data.infraguard.helpers

# Rule metadata with i18n support
rule_meta := {
	"id": "alb-instance-bind-security-group-or-enabled-acl",
	"severity": "medium",
	"name": {
		"en": "ALB Instance Bind Security Group or Enable ACL",
		"zh": "ALB 实例关联安全组或者为所有监听设置访问控制",
		"ja": "ALB インスタンスセキュリティグループのバインドまたは ACL の有効化",
		"de": "ALB-Instanz Sicherheitsgruppe binden oder ACL aktivieren",
		"es": "Instancia ALB Vincular Grupo de Seguridad o Habilitar ACL",
		"fr": "Instance ALB Lier Groupe de Sécurité ou Activer ACL",
		"pt": "Instância ALB Vincular Grupo de Segurança ou Habilitar ACL"
	},
	"description": {
		"en": "ALB instance should have security groups associated or ACL configured for all running listeners.",
		"zh": "ALB 实例关联了安全组或者为所有运行中的监听都设置了访问控制，视为合规。不存在运行中监听的实例不适用本规则，视为不适用。",
		"ja": "ALB インスタンスは、セキュリティグループが関連付けられているか、すべての実行中のリスナーに ACL が設定されている必要があります。",
		"de": "ALB-Instanz sollte Sicherheitsgruppen zugeordnet haben oder ACL für alle laufenden Listener konfiguriert haben.",
		"es": "La instancia ALB debe tener grupos de seguridad asociados o ACL configurado para todos los oyentes en ejecución.",
		"fr": "L'instance ALB doit avoir des groupes de sécurité associés ou ACL configuré pour tous les écouteurs en cours d'exécution.",
		"pt": "A instância ALB deve ter grupos de segurança associados ou ACL configurado para todos os ouvintes em execução."
	},
	"reason": {
		"en": "ALB instance does not have security groups associated, which may expose the load balancer to security risks.",
		"zh": "ALB 实例未关联安全组，可能导致负载均衡器面临安全风险。",
		"ja": "ALB インスタンスにセキュリティグループが関連付けられていないため、ロードバランサーがセキュリティリスクにさらされる可能性があります。",
		"de": "ALB-Instanz hat keine Sicherheitsgruppen zugeordnet, was den Load Balancer Sicherheitsrisiken aussetzen kann.",
		"es": "La instancia ALB no tiene grupos de seguridad asociados, lo que puede exponer el equilibrador de carga a riesgos de seguridad.",
		"fr": "L'instance ALB n'a pas de groupes de sécurité associés, ce qui peut exposer l'équilibreur de charge à des risques de sécurité.",
		"pt": "A instância ALB não tem grupos de segurança associados, o que pode expor o balanceador de carga a riscos de segurança."
	},
	"recommendation": {
		"en": "Associate security groups with the ALB instance by configuring SecurityGroupIds property, or set up ACL for all listeners.",
		"zh": "通过配置 SecurityGroupIds 属性为 ALB 实例关联安全组，或为所有监听器设置访问控制列表(ACL)。",
		"ja": "SecurityGroupIds プロパティを設定して ALB インスタンスにセキュリティグループを関連付けるか、すべてのリスナーに ACL を設定します。",
		"de": "Ordnen Sie Sicherheitsgruppen der ALB-Instanz zu, indem Sie die Eigenschaft SecurityGroupIds konfigurieren, oder richten Sie ACL für alle Listener ein.",
		"es": "Asocie grupos de seguridad con la instancia ALB configurando la propiedad SecurityGroupIds, o configure ACL para todos los oyentes.",
		"fr": "Associez des groupes de sécurité à l'instance ALB en configurant la propriété SecurityGroupIds, ou configurez ACL pour tous les écouteurs.",
		"pt": "Associe grupos de segurança à instância ALB configurando a propriedade SecurityGroupIds, ou configure ACL para todos os ouvintes."
	},
	"resource_types": ["ALIYUN::ALB::LoadBalancer"]
}

# Check if security groups are configured
has_security_groups(resource) if {
	count(resource.Properties.SecurityGroupIds) > 0
}

# Generate deny for non-compliant resources
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ALB::LoadBalancer")
	not has_security_groups(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityGroupIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
