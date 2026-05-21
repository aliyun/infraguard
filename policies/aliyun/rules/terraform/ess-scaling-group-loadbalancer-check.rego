package infraguard.rules.terraform.ess_scaling_group_loadbalancer_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "ess-scaling-group-loadbalancer-check",
	"severity": "medium",
	"name": {
		"en": "ESS Scaling Group Load Balancer Existence Check",
		"zh": "弹性伸缩组关联负载均衡存在性检测",
		"ja": "ESS スケーリンググループロードバランサー存在チェック",
		"de": "ESS-Skalierungsgruppe Load Balancer Existenzprüfung",
		"es": "Verificación de Existencia de Equilibrador de Carga del Grupo de Escalado ESS",
		"fr": "Vérification d'Existence de l'Équilibreur de Charge du Groupe de Mise à l'Échelle ESS",
		"pt": "Verificação de Existência do Balanceador de Carga do Grupo de Escalonamento ESS"
	},
	"description": {
		"en": "ESS scaling groups should be attached to load balancers for traffic distribution.",
		"zh": "弹性伸缩组关联传统型负载均衡或者应用负载均衡仍然为保有中资源，视为合规。",
		"ja": "ESS スケーリンググループは、適切なトラフィック分散のために既存のアクティブなロードバランサーインスタンスにアタッチする必要があります。",
		"de": "ESS-Skalierungsgruppen sollten an vorhandene und aktive Load Balancer-Instanzen angehängt werden, um eine ordnungsgemäße Datenverteilung zu gewährleisten.",
		"es": "Los grupos de escalado ESS deben estar adjuntos a instancias de equilibrador de carga existentes y activas para una distribución adecuada del tráfico.",
		"fr": "Les groupes de mise à l'échelle ESS doivent être attachés à des instances d'équilibreur de charge existantes et actives pour une distribution appropriée du trafic.",
		"pt": "Os grupos de escalonamento ESS devem estar anexados a instâncias de balanceador de carga existentes e ativas para distribuição adequada de tráfego."
	},
	"reason": {
		"en": "The ESS scaling group does not declare a load balancer attachment.",
		"zh": "弹性伸缩组关联的负载均衡可能已不存在或已失效。",
		"ja": "ESS スケーリンググループが存在しないか非アクティブなロードバランサーにアタッチされている可能性があります。",
		"de": "Die ESS-Skalierungsgruppe kann an einen Load Balancer angehängt sein, der nicht mehr existiert oder inaktiv ist.",
		"es": "El grupo de escalado ESS puede estar adjunto a un equilibrador de carga que ya no existe o está inactivo.",
		"fr": "Le groupe de mise à l'échelle ESS peut être attaché à un équilibreur de charge qui n'existe plus ou est inactif.",
		"pt": "O grupo de escalonamento ESS pode estar anexado a um balanceador de carga que não existe mais ou está inativo."
	},
	"recommendation": {
		"en": "Declare loadbalancer_ids or server group attachments for the scaling group.",
		"zh": "确保伸缩组中引用的负载均衡 ID 是有效的保有中资源。",
		"ja": "スケーリンググループで参照されているロードバランサー ID が有効でアクティブなリソースであることを確認します。",
		"de": "Stellen Sie sicher, dass die in der Skalierungsgruppe referenzierten Load Balancer-IDs gültige und aktive Ressourcen sind.",
		"es": "Asegúrese de que los ID de equilibrador de carga referenciados en el grupo de escalado sean recursos válidos y activos.",
		"fr": "Assurez-vous que les ID d'équilibreur de charge référencés dans le groupe de mise à l'échelle sont des ressources valides et actives.",
		"pt": "Garanta que os IDs de balanceador de carga referenciados no grupo de escalonamento sejam recursos válidos e ativos."
	},
	"resource_types": ["alicloud_ess_scaling_group", "alicloud_ess_scalinggroup_vserver_groups"],
	"iac_type": "terraform"
}

has_load_balancer(resource) if {
	loadbalancer_ids := tf.get_attribute(resource, "loadbalancer_ids", [])
	not tf.is_unknown(loadbalancer_ids)
	count(loadbalancer_ids) > 0
}

has_load_balancer(resource) if {
	load_balancer_ids := tf.get_attribute(resource, "load_balancer_ids", [])
	not tf.is_unknown(load_balancer_ids)
	count(load_balancer_ids) > 0
}

has_load_balancer(resource) if {
	server_groups := tf.get_attribute(resource, "server_groups", [])
	not tf.is_unknown(server_groups)
	count(server_groups) > 0
}

has_vserver_group_attachment(name) if {
	some _, attachment in tf.resources_by_type("alicloud_ess_scalinggroup_vserver_groups")
	scaling_group_id := tf.get_attribute(attachment, "scaling_group_id", "")
	scaling_group_id == sprintf("alicloud_ess_scaling_group.%s", [name])
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_ess_scaling_group")
	not has_load_balancer(resource)
	not has_vserver_group_attachment(name)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_ess_scaling_group.%s", [name]),
		"violation_path": ["loadbalancer_ids"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
