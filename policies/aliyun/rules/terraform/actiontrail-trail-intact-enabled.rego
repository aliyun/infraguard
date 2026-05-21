package infraguard.rules.terraform.actiontrail_trail_intact_enabled

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "actiontrail-trail-intact-enabled",
	"severity": "high",
	"name": {
		"en": "ActionTrail Trail Intact Enabled",
		"zh": "开启操作审计全量日志跟踪",
		"ja": "ActionTrail トレイルが完全に有効",
		"de": "ActionTrail Trail vollständig aktiviert",
		"es": "Trilha ActionTrail Intacta Habilitada",
		"fr": "Piste ActionTrail Intacte Activée",
		"pt": "Trilha ActionTrail Intacta Habilitada"
	},
	"description": {
		"en": "ActionTrail trail should be enabled and track all event types (Read and Write).",
		"zh": "操作审计中存在开启状态的跟踪，且跟踪全部地域和全部事件类型。",
		"ja": "ActionTrail トレイルを有効にし、すべてのイベントタイプ（読み取りと書き込み）を追跡する必要があります。",
		"de": "ActionTrail Trail sollte aktiviert sein und alle Ereignistypen (Lesen und Schreiben) verfolgen.",
		"es": "La trilha ActionTrail debe estar habilitada y rastrear todos los tipos de eventos (Lectura y Escritura).",
		"fr": "La piste ActionTrail doit être activée et suivre tous les types d'événements (Lecture et Écriture).",
		"pt": "A trilha ActionTrail deve estar habilitada e rastrear todos os tipos de eventos (Leitura e Escrita)."
	},
	"reason": {
		"en": "The ActionTrail trail is not enabled or does not track all event types.",
		"zh": "操作审计跟踪未开启或未跟踪所有事件类型。",
		"ja": "ActionTrail トレイルが有効になっていないか、すべてのイベントタイプを追跡していません。",
		"de": "Der ActionTrail Trail ist nicht aktiviert oder verfolgt nicht alle Ereignistypen.",
		"es": "La trilha ActionTrail no está habilitada o no rastrea todos los tipos de eventos.",
		"fr": "La piste ActionTrail n'est pas activée ou ne suit pas tous les types d'événements.",
		"pt": "A trilha ActionTrail não está habilitada ou não rastreia todos os tipos de eventos."
	},
	"recommendation": {
		"en": "Set event_rw to \"All\" and status to \"Enable\" on the alicloud_actiontrail_trail resource.",
		"zh": "在 alicloud_actiontrail_trail 资源上将 event_rw 设置为 \"All\"，status 设置为 \"Enable\"。",
		"ja": "alicloud_actiontrail_trail リソースで event_rw を \"All\"、status を \"Enable\" に設定します。",
		"de": "Setzen Sie event_rw auf \"All\" und status auf \"Enable\" für die alicloud_actiontrail_trail-Ressource.",
		"es": "Establezca event_rw en \"All\" y status en \"Enable\" en el recurso alicloud_actiontrail_trail.",
		"fr": "Définissez event_rw sur \"All\" et status sur \"Enable\" sur la ressource alicloud_actiontrail_trail.",
		"pt": "Defina event_rw como \"All\" e status como \"Enable\" no recurso alicloud_actiontrail_trail."
	},
	"resource_types": ["alicloud_actiontrail_trail"],
	"iac_type": "terraform"
}

# Check if trail tracks all event types
is_track_all_events(resource) if {
	event_rw := tf.get_attribute(resource, "event_rw", "Write")
	not tf.is_unknown(event_rw)
	event_rw == "All"
}

# Check if trail is enabled
is_trail_enabled(resource) if {
	status := tf.get_attribute(resource, "status", "Disable")
	not tf.is_unknown(status)
	status == "Enable"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_actiontrail_trail")
	not is_track_all_events(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_actiontrail_trail.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_actiontrail_trail")
	is_track_all_events(resource)
	not is_trail_enabled(resource)
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_actiontrail_trail.%s", [name]),
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
