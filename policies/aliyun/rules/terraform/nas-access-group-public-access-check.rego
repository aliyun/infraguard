package infraguard.rules.terraform.nas_access_group_public_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "nas-access-group-public-access-check",
	"severity": "high",
	"name": {
		"en": "NAS Access Group IP Restriction",
		"zh": "NAS 权限组禁用公网授权",
		"ja": "NAS アクセスグループ IP 制限",
		"de": "NAS-Zugriffsgruppe IP-Beschränkung",
		"es": "Restricción de IP del Grupo de Acceso NAS",
		"fr": "Restriction IP du Groupe d'Accès NAS",
		"pt": "Restrição de IP do Grupo de Acesso NAS"
	},
	"description": {
		"en": "Ensures that NAS access rules do not allow unrestricted access from all IP addresses (0.0.0.0/0).",
		"zh": "确保 NAS 访问规则不允许所有 IP 地址（0.0.0.0/0）的无限制访问。",
		"ja": "NAS アクセスルールがすべての IP アドレス（0.0.0.0/0）からの無制限アクセスを許可していないことを確認します。",
		"de": "Stellt sicher, dass NAS-Zugriffsregeln keinen uneingeschränkten Zugriff von allen IP-Adressen (0.0.0.0/0) erlauben.",
		"es": "Garantiza que las reglas de acceso NAS no permitan acceso sin restricciones desde todas las direcciones IP (0.0.0.0/0).",
		"fr": "Garantit que les règles d'accès NAS n'autorisent pas l'accès illimité depuis toutes les adresses IP (0.0.0.0/0).",
		"pt": "Garante que as regras de acesso NAS não permitam acesso irrestrito de todos os endereços IP (0.0.0.0/0)."
	},
	"reason": {
		"en": "The NAS access rule allows access from 0.0.0.0/0, which permits any IP to access the file system, significantly increasing security risks.",
		"zh": "NAS 访问规则允许来自 0.0.0.0/0 的访问，这允许任何 IP 访问文件系统，大大增加了安全风险。",
		"ja": "NAS アクセスルールが 0.0.0.0/0 からのアクセスを許可しているため、任意の IP がファイルシステムにアクセスでき、セキュリティリスクが大幅に増加します。",
		"de": "Die NAS-Zugriffsregel erlaubt den Zugriff von 0.0.0.0/0, was jeder IP den Zugriff auf das Dateisystem ermöglicht und die Sicherheitsrisiken erheblich erhöht.",
		"es": "La regla de acceso NAS permite el acceso desde 0.0.0.0/0, lo que permite que cualquier IP acceda al sistema de archivos, aumentando significativamente los riesgos de seguridad.",
		"fr": "La règle d'accès NAS autorise l'accès depuis 0.0.0.0/0, ce qui permet à n'importe quelle IP d'accéder au système de fichiers, augmentant considérablement les risques de sécurité.",
		"pt": "A regra de acesso NAS permite acesso de 0.0.0.0/0, o que permite que qualquer IP acesse o sistema de arquivos, aumentando significativamente os riscos de segurança."
	},
	"recommendation": {
		"en": "Restrict the source_cidr_ip to specific IP ranges instead of allowing all IPs (0.0.0.0/0).",
		"zh": "将 source_cidr_ip 限制为特定的 IP 范围，而不是允许所有 IP（0.0.0.0/0）。",
		"ja": "すべての IP（0.0.0.0/0）を許可するのではなく、source_cidr_ip を特定の IP 範囲に制限します。",
		"de": "Beschränken Sie source_cidr_ip auf spezifische IP-Bereiche, anstatt alle IPs (0.0.0.0/0) zuzulassen.",
		"es": "Restrinja source_cidr_ip a rangos de IP específicos en lugar de permitir todas las IPs (0.0.0.0/0).",
		"fr": "Restreignez source_cidr_ip à des plages d'IP spécifiques au lieu d'autoriser toutes les IP (0.0.0.0/0).",
		"pt": "Restrinja source_cidr_ip a intervalos de IP específicos em vez de permitir todos os IPs (0.0.0.0/0)."
	},
	"resource_types": ["alicloud_nas_access_rule"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_nas_access_rule")
	source_cidr := tf.get_attribute(resource, "source_cidr_ip", "")
	source_cidr == "0.0.0.0/0"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_nas_access_rule.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
