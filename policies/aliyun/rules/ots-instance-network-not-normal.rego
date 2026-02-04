package infraguard.rules.aliyun.ots_instance_network_not_normal

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "ots-instance-network-not-normal",
	"name": {
		"en": "OTS Restricted Network Type",
		"zh": "OTS 实例限制网络类型",
		"ja": "OTS 制限ネットワークタイプ",
		"de": "OTS eingeschränkter Netzwerktyp",
		"es": "Tipo de Red Restringido OTS",
		"fr": "Type de Réseau Restreint OTS",
		"pt": "Tipo de Rede Restrito OTS"
	},
	"severity": "medium",
	"description": {
		"en": "Ensures Table Store (OTS) instances do not use the 'Normal' (unrestricted) network type.",
		"zh": "确保表格存储（OTS）实例未使用 'Normal'（无限制）网络类型。",
		"ja": "Table Store（OTS）インスタンスが 'Normal'（無制限）ネットワークタイプを使用していないことを確認します。",
		"de": "Stellt sicher, dass Table Store (OTS)-Instanzen nicht den 'Normal' (uneingeschränkten) Netzwerktyp verwenden.",
		"es": "Garantiza que las instancias de Table Store (OTS) no usen el tipo de red 'Normal' (sin restricciones).",
		"fr": "Garantit que les instances Table Store (OTS) n'utilisent pas le type de réseau 'Normal' (sans restriction).",
		"pt": "Garante que as instâncias do Table Store (OTS) não usem o tipo de rede 'Normal' (sem restrições)."
	},
	"reason": {
		"en": "Using VPC or bound-VPC network types provides better isolation than the Normal type.",
		"zh": "使用 VPC 或绑定 VPC 网络类型比 Normal 类型提供更好的隔离性。",
		"ja": "VPC またはバインド VPC ネットワークタイプを使用すると、Normal タイプよりも優れた分離が提供されます。",
		"de": "Die Verwendung von VPC- oder gebundenen VPC-Netzwerktypen bietet bessere Isolation als der Normal-Typ.",
		"es": "Usar tipos de red VPC o VPC vinculado proporciona mejor aislamiento que el tipo Normal.",
		"fr": "L'utilisation de types de réseau VPC ou VPC lié offre une meilleure isolation que le type Normal.",
		"pt": "Usar tipos de rede VPC ou VPC vinculado fornece melhor isolamento do que o tipo Normal."
	},
	"recommendation": {
		"en": "Set Network to 'Vpc' or 'VpcAndConsole' for the OTS instance.",
		"zh": "为 OTS 实例将 Network 设置为 'Vpc' 或 'VpcAndConsole'。",
		"ja": "OTS インスタンスの Network を 'Vpc' または 'VpcAndConsole' に設定します。",
		"de": "Setzen Sie Network für die OTS-Instanz auf 'Vpc' oder 'VpcAndConsole'.",
		"es": "Establezca Network en 'Vpc' o 'VpcAndConsole' para la instancia OTS.",
		"fr": "Définissez Network sur 'Vpc' ou 'VpcAndConsole' pour l'instance OTS.",
		"pt": "Defina Network como 'Vpc' ou 'VpcAndConsole' para a instância OTS."
	},
	"resource_types": ["ALIYUN::OTS::Instance"],
}

is_compliant(resource) if {
	net := helpers.get_property(resource, "Network", "Normal")
	net != "Normal"
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::OTS::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "Network"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
