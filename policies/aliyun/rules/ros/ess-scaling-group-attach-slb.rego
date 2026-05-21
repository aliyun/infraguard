package infraguard.rules.aliyun.ess_scaling_group_attach_slb

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-group-attach-slb",
	"severity": "medium",
	"name": {
		"en": "ESS Scaling Group Attach SLB",
		"zh": "弹性伸缩组设置关联负载均衡",
		"ja": "ESS スケーリンググループ SLB アタッチ",
		"de": "ESS-Skalierungsgruppe SLB anhängen",
		"es": "Grupo de Escalado ESS Adjuntar SLB",
		"fr": "Groupe de Mise à l'Échelle ESS Attacher SLB",
		"pt": "Grupo de Escalonamento ESS Anexar SLB"
	},
	"description": {
		"en": "ESS scaling groups should be attached to Classic Load Balancer (SLB) for proper traffic distribution.",
		"zh": "弹性伸缩组关联传统型负载均衡，视为合规。",
		"ja": "ESS スケーリンググループは、適切なトラフィック分散のためにクラシックロードバランサー（SLB）にアタッチする必要があります。",
		"de": "ESS-Skalierungsgruppen sollten an Classic Load Balancer (SLB) angehängt werden, um eine ordnungsgemäße Verkehrsverteilung zu gewährleisten.",
		"es": "Los grupos de escalado ESS deben adjuntarse al Equilibrador de Carga Clásico (SLB) para una distribución adecuada del tráfico.",
		"fr": "Les groupes de mise à l'échelle ESS doivent être attachés à l'Équilibreur de Charge Classique (SLB) pour une distribution appropriée du trafic.",
		"pt": "Os grupos de escalonamento ESS devem ser anexados ao Balanceador de Carga Clássico (SLB) para distribuição adequada de tráfego."
	},
	"reason": {
		"en": "The ESS scaling group is not attached to a Classic Load Balancer, which may affect traffic distribution.",
		"zh": "弹性伸缩组未关联传统型负载均衡，可能影响流量的分发和可用性。",
		"ja": "ESS スケーリンググループがクラシックロードバランサーにアタッチされていないため、トラフィック分散に影響を与える可能性があります。",
		"de": "Die ESS-Skalierungsgruppe ist nicht an einen Classic Load Balancer angehängt, was die Verkehrsverteilung beeinträchtigen kann.",
		"es": "El grupo de escalado ESS no está adjunto a un Equilibrador de Carga Clásico, lo que puede afectar la distribución del tráfico.",
		"fr": "Le groupe de mise à l'échelle ESS n'est pas attaché à un Équilibreur de Charge Classique, ce qui peut affecter la distribution du trafic.",
		"pt": "O grupo de escalonamento ESS não está anexado a um Balanceador de Carga Clássico, o que pode afetar a distribuição de tráfego."
	},
	"recommendation": {
		"en": "Attach the scaling group to a Classic Load Balancer using the LoadBalancerIds property.",
		"zh": "使用 LoadBalancerIds 属性将伸缩组关联到传统型负载均衡实例。",
		"ja": "LoadBalancerIds プロパティを使用して、スケーリンググループをクラシックロードバランサーにアタッチします。",
		"de": "Hängen Sie die Skalierungsgruppe mit der Eigenschaft LoadBalancerIds an einen Classic Load Balancer an.",
		"es": "Adjunte el grupo de escalado a un Equilibrador de Carga Clásico usando la propiedad LoadBalancerIds.",
		"fr": "Attachez le groupe de mise à l'échelle à un Équilibreur de Charge Classique en utilisant la propriété LoadBalancerIds.",
		"pt": "Anexe o grupo de escalonamento a um Balanceador de Carga Clássico usando a propriedade LoadBalancerIds."
	},
	"resource_types": ["ALIYUN::ESS::ScalingGroup"]
}

# Check if scaling group has Classic Load Balancer attached
has_classic_slb(resource) if {
	load_balancer_ids := helpers.get_property(resource, "LoadBalancerIds", [])
	count(load_balancer_ids) > 0
}

# Deny rule: ESS scaling groups should be attached to Classic Load Balancer
deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingGroup")
	not has_classic_slb(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "LoadBalancerIds"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
