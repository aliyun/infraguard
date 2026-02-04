package infraguard.rules.aliyun.cr_instance_any_ip_access_check

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "cr-instance-any-ip-access-check",
	"name": {
		"en": "CR Instance No Any IP Access",
		"zh": "容器镜像服务实例白名单检测",
		"ja": "CR インスタンスに任意の IP アクセスがない",
		"de": "CR-Instanz Kein Beliebiger IP-Zugriff",
		"es": "Instancia CR Sin Acceso de Cualquier IP",
		"fr": "Instance CR Sans Accès IP Quelconque",
		"pt": "Instância CR Sem Acesso de Qualquer IP",
	},
	"severity": "high",
	"description": {
		"en": "Ensures Container Registry instances do not have any IP (0.0.0.0/0) in their whitelist.",
		"zh": "确保容器镜像服务实例的白名单中不包含任意 IP（0.0.0.0/0）。",
		"ja": "コンテナレジストリインスタンスのホワイトリストに任意の IP（0.0.0.0/0）が含まれていないことを確認します。",
		"de": "Stellt sicher, dass Container Registry-Instanzen keine beliebige IP (0.0.0.0/0) in ihrer Whitelist haben.",
		"es": "Garantiza que las instancias de Container Registry no tengan ninguna IP (0.0.0.0/0) en su lista blanca.",
		"fr": "Garantit que les instances Container Registry n'ont pas d'IP quelconque (0.0.0.0/0) dans leur liste blanche.",
		"pt": "Garante que as instâncias do Container Registry não tenham qualquer IP (0.0.0.0/0) em sua lista branca.",
	},
	"reason": {
		"en": "Allowing any IP (0.0.0.0/0) in the whitelist exposes the container registry to potential unauthorized access from any internet user.",
		"zh": "在白名单中允许任意 IP（0.0.0.0/0）会使容器镜像服务面临来自任何互联网用户的潜在未授权访问风险。",
		"ja": "ホワイトリストで任意の IP（0.0.0.0/0）を許可すると、コンテナレジストリが任意のインターネットユーザーからの不正アクセスのリスクにさらされます。",
		"de": "Das Zulassen beliebiger IPs (0.0.0.0/0) in der Whitelist setzt die Container Registry potenziell unbefugtem Zugriff von jedem Internetbenutzer aus.",
		"es": "Permitir cualquier IP (0.0.0.0/0) en la lista blanca expone el registro de contenedores a acceso no autorizado potencial de cualquier usuario de Internet.",
		"fr": "Autoriser n'importe quelle IP (0.0.0.0/0) dans la liste blanche expose le registre de conteneurs à un accès non autorisé potentiel de n'importe quel utilisateur Internet.",
		"pt": "Permitir qualquer IP (0.0.0.0/0) na lista branca expõe o registro de contêineres a acesso não autorizado potencial de qualquer usuário da Internet.",
	},
	"recommendation": {
		"en": "Remove 0.0.0.0/0 from the whitelist and specify specific IP ranges.",
		"zh": "从白名单中移除 0.0.0.0/0，并指定具体的 IP 范围。",
		"ja": "ホワイトリストから 0.0.0.0/0 を削除し、特定の IP 範囲を指定します。",
		"de": "Entfernen Sie 0.0.0.0/0 aus der Whitelist und geben Sie spezifische IP-Bereiche an.",
		"es": "Elimine 0.0.0.0/0 de la lista blanca y especifique rangos de IP específicos.",
		"fr": "Supprimez 0.0.0.0/0 de la liste blanche et spécifiez des plages d'IP spécifiques.",
		"pt": "Remova 0.0.0.0/0 da lista branca e especifique intervalos de IP específicos.",
	},
	"resource_types": ["ALIYUN::CR::Instance"],
}

# Check if any ACL policy has 0.0.0.0/0 and is associated with a CR instance
has_any_ip_access(cr_instance_name) if {
	some acl_name, acl_resource in helpers.resources_by_type("ALIYUN::CR::InstanceEndpointAclPolicy")

	# Check if the entry is 0.0.0.0/0 (any IP)
	entry := helpers.get_property(acl_resource, "Entry", "")
	entry == "0.0.0.0/0"

	# Get the instance ID from the ACL policy (could be a GetAtt reference or string)
	instance_id_prop := helpers.get_property(acl_resource, "InstanceId", "")

	# Check if InstanceId is a GetAtt reference pointing to this CR instance
	helpers.is_get_att_referencing(instance_id_prop, cr_instance_name)
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::CR::Instance")
	has_any_ip_access(name)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
