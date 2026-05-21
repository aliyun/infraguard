package infraguard.rules.terraform.ess_scaling_group_attach_slb

import rego.v1

import data.infraguard.helpers.terraform as tf

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
		"en": "ESS scaling groups should be attached to Classic Load Balancer.",
		"zh": "弹性伸缩组关联传统型负载均衡，视为合规。",
		"ja": "ESS スケーリンググループは、適切なトラフィック分散のためにクラシックロードバランサー（SLB）にアタッチする必要があります。",
		"de": "ESS-Skalierungsgruppen sollten an Classic Load Balancer (SLB) angehängt werden, um eine ordnungsgemäße Verkehrsverteilung zu gewährleisten.",
		"es": "Los grupos de escalado ESS deben adjuntarse al Equilibrador de Carga Clásico (SLB) para una distribución adecuada del tráfico.",
		"fr": "Les groupes de mise à l'échelle ESS doivent être attachés à l'Équilibreur de Charge Classique (SLB) pour une distribution appropriée du trafic.",
		"pt": "Os grupos de escalonamento ESS devem ser anexados ao Balanceador de Carga Clássico (SLB) para distribuição adequada de tráfego."
	},
	"reason": {
		"en": "The ESS scaling group is not attached to a Classic Load Balancer.",
		"zh": "弹性伸缩组未关联传统型负载均衡，可能影响流量的分发和可用性。",
		"ja": "ESS スケーリンググループがクラシックロードバランサーにアタッチされていないため、トラフィック分散に影響を与える可能性があります。",
		"de": "Die ESS-Skalierungsgruppe ist nicht an einen Classic Load Balancer angehängt, was die Verkehrsverteilung beeinträchtigen kann.",
		"es": "El grupo de escalado ESS no está adjunto a un Equilibrador de Carga Clásico, lo que puede afectar la distribución del tráfico.",
		"fr": "Le groupe de mise à l'échelle ESS n'est pas attaché à un Équilibreur de Charge Classique, ce qui peut affecter la distribution du trafic.",
		"pt": "O grupo de escalonamento ESS não está anexado a um Balanceador de Carga Clássico, o que pode afetar a distribuição de tráfego."
	},
	"recommendation": {
		"en": "Set loadbalancer_ids on the scaling group.",
		"zh": "使用 LoadBalancerIds 属性将伸缩组关联到传统型负载均衡实例。",
		"ja": "LoadBalancerIds プロパティを使用して、スケーリンググループをクラシックロードバランサーにアタッチします。",
		"de": "Hängen Sie die Skalierungsgruppe mit der Eigenschaft LoadBalancerIds an einen Classic Load Balancer an.",
		"es": "Adjunte el grupo de escalado a un Equilibrador de Carga Clásico usando la propiedad LoadBalancerIds.",
		"fr": "Attachez le groupe de mise à l'échelle à un Équilibreur de Charge Classique en utilisant la propriété LoadBalancerIds.",
		"pt": "Anexe o grupo de escalonamento a um Balanceador de Carga Clássico usando a propriedade LoadBalancerIds."
	},
	"resource_types": ["alicloud_ess_scaling_group"],
	"iac_type": "terraform"
}

has_classic_slb(resource) if {
	loadbalancer_ids := tf.get_attribute(resource, "loadbalancer_ids", [])
	not tf.is_unknown(loadbalancer_ids)
	count(loadbalancer_ids) > 0
}

has_classic_slb(resource) if {
	load_balancer_ids := tf.get_attribute(resource, "load_balancer_ids", [])
	not tf.is_unknown(load_balancer_ids)
	count(load_balancer_ids) > 0
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_group")
	not has_classic_slb(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_group.%s", [name]),
		"violation_path": ["loadbalancer_ids"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
