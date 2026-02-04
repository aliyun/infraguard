package infraguard.rules.aliyun.mongodb_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "mongodb-public-and-any-ip-access-check",
	"severity": "high",
	"name": {
		"en": "MongoDB Public and Any IP Access Check",
		"zh": "MongoDB 实例不开启公网或安全白名单不设置为允许任意来源访问",
		"ja": "MongoDB のパブリックおよび任意の IP アクセスチェック",
		"de": "MongoDB öffentlicher und beliebiger IP-Zugriff-Prüfung",
		"es": "Verificación de Acceso Público y de Cualquier IP de MongoDB",
		"fr": "Vérification d'Accès Public et de N'importe Quelle IP MongoDB",
		"pt": "Verificação de Acesso Público e de Qualquer IP do MongoDB"
	},
	"description": {
		"en": "Ensures that MongoDB instances do not have an open whitelist (0.0.0.0/0).",
		"zh": "确保 MongoDB 实例未设置开放白名单（0.0.0.0/0）。",
		"ja": "MongoDB インスタンスにオープンホワイトリスト（0.0.0.0/0）が設定されていないことを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen keine offene Whitelist (0.0.0.0/0) haben.",
		"es": "Garantiza que las instancias MongoDB no tengan una lista blanca abierta (0.0.0.0/0).",
		"fr": "Garantit que les instances MongoDB n'ont pas de liste blanche ouverte (0.0.0.0/0).",
		"pt": "Garante que as instâncias MongoDB não tenham uma lista branca aberta (0.0.0.0/0)."
	},
	"reason": {
		"en": "Setting the whitelist to 0.0.0.0/0 allows any IP to attempt connection, significantly increasing the risk of data breaches or brute force attacks.",
		"zh": "将白名单设置为 0.0.0.0/0 允许任何 IP 尝试连接，大大增加了数据泄露或暴力破解的风险。",
		"ja": "ホワイトリストを 0.0.0.0/0 に設定すると、任意の IP が接続を試みることができ、データ侵害やブルートフォース攻撃のリスクが大幅に増加します。",
		"de": "Das Setzen der Whitelist auf 0.0.0.0/0 erlaubt jeder IP, eine Verbindung zu versuchen, was das Risiko von Datenlecks oder Brute-Force-Angriffen erheblich erhöht.",
		"es": "Establecer la lista blanca en 0.0.0.0/0 permite que cualquier IP intente conectarse, aumentando significativamente el riesgo de violaciones de datos o ataques de fuerza bruta.",
		"fr": "Définir la liste blanche sur 0.0.0.0/0 permet à n'importe quelle IP de tenter une connexion, augmentant considérablement le risque de violations de données ou d'attaques par force brute.",
		"pt": "Definir a lista branca como 0.0.0.0/0 permite que qualquer IP tente conexão, aumentando significativamente o risco de violações de dados ou ataques de força bruta."
	},
	"recommendation": {
		"en": "Restrict the IP whitelist for the MongoDB instance to specific trusted IP ranges.",
		"zh": "将 MongoDB 实例的 IP 白名单限制为特定的可信 IP 范围。",
		"ja": "MongoDB インスタンスの IP ホワイトリストを特定の信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie die IP-Whitelist für die MongoDB-Instanz auf spezifische vertrauenswürdige IP-Bereiche.",
		"es": "Restrinja la lista blanca de IP para la instancia MongoDB a rangos de IP confiables específicos.",
		"fr": "Restreignez la liste blanche IP pour l'instance MongoDB à des plages d'IP de confiance spécifiques.",
		"pt": "Restrinja a lista branca de IP para a instância MongoDB a intervalos de IP confiáveis específicos."
	},
	"resource_types": ["ALIYUN::MONGODB::Instance"]
}

is_compliant(resource) if {
	# Check SecurityIPArray property (string)
	whitelist_str := helpers.get_property(resource, "SecurityIPArray", "")
	whitelist := split(whitelist_str, ",")
	not has_open_cidr(whitelist)
}

has_open_cidr(whitelist) if {
	some cidr in whitelist
	helpers.is_public_cidr(trim_space(cidr))
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MONGODB::Instance")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "SecurityIPArray"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
