package infraguard.rules.terraform.mongodb_public_and_any_ip_access_check

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "mongodb-public-and-any-ip-access-check",
	"severity": "high",
	"name": {
		"en": "MongoDB Instance Network Type Check",
		"zh": "MongoDB 实例网络类型检查",
		"ja": "MongoDB のパブリックおよび任意の IP アクセスチェック",
		"de": "MongoDB öffentlicher und beliebiger IP-Zugriff-Prüfung",
		"es": "Verificación de Acceso Público y de Cualquier IP de MongoDB",
		"fr": "Vérification d'Accès Public et de N'importe Quelle IP MongoDB",
		"pt": "Verificação de Acesso Público e de Qualquer IP do MongoDB"
	},
	"description": {
		"en": "MongoDB instances should use VPC network type instead of Classic network to reduce public exposure.",
		"zh": "MongoDB 实例应使用 VPC 网络类型而非经典网络，以减少公网暴露风险。",
		"ja": "MongoDB インスタンスにオープンホワイトリスト（0.0.0.0/0）が設定されていないことを確認します。",
		"de": "Stellt sicher, dass MongoDB-Instanzen keine offene Whitelist (0.0.0.0/0) haben.",
		"es": "Garantiza que las instancias MongoDB no tengan una lista blanca abierta (0.0.0.0/0).",
		"fr": "Garantit que les instances MongoDB n'ont pas de liste blanche ouverte (0.0.0.0/0).",
		"pt": "Garante que as instâncias MongoDB não tenham uma lista branca aberta (0.0.0.0/0)."
	},
	"reason": {
		"en": "The MongoDB instance is using Classic network type which may expose it to public access.",
		"zh": "MongoDB 实例使用了经典网络类型，可能暴露于公网访问。",
		"ja": "ホワイトリストを 0.0.0.0/0 に設定すると、任意の IP が接続を試みることができ、データ侵害やブルートフォース攻撃のリスクが大幅に増加します。",
		"de": "Das Setzen der Whitelist auf 0.0.0.0/0 erlaubt jeder IP, eine Verbindung zu versuchen, was das Risiko von Datenlecks oder Brute-Force-Angriffen erheblich erhöht.",
		"es": "Establecer la lista blanca en 0.0.0.0/0 permite que cualquier IP intente conectarse, aumentando significativamente el riesgo de violaciones de datos o ataques de fuerza bruta.",
		"fr": "Définir la liste blanche sur 0.0.0.0/0 permet à n'importe quelle IP de tenter une connexion, augmentant considérablement le risque de violations de données ou d'attaques par force brute.",
		"pt": "Definir a lista branca como 0.0.0.0/0 permite que qualquer IP tente conexão, aumentando significativamente o risco de violações de dados ou ataques de força bruta."
	},
	"recommendation": {
		"en": "Set network_type to 'VPC' to use VPC network for better isolation.",
		"zh": "将 network_type 设置为 'VPC' 以使用 VPC 网络实现更好的隔离。",
		"ja": "MongoDB インスタンスの IP ホワイトリストを特定の信頼できる IP 範囲に制限します。",
		"de": "Beschränken Sie die IP-Whitelist für die MongoDB-Instanz auf spezifische vertrauenswürdige IP-Bereiche.",
		"es": "Restrinja la lista blanca de IP para la instancia MongoDB a rangos de IP confiables específicos.",
		"fr": "Restreignez la liste blanche IP pour l'instance MongoDB à des plages d'IP de confiance spécifiques.",
		"pt": "Restrinja a lista branca de IP para a instância MongoDB a intervalos de IP confiáveis específicos."
	},
	"resource_types": ["alicloud_mongodb_instance"],
	"iac_type": "terraform"
}

deny contains violation if {
	some name, resource in tf.resources_by_type("alicloud_mongodb_instance")
	tf.get_attribute(resource, "network_type", "Classic") != "VPC"
	violation := {
		"id": rule_meta.id,
		"resource_id": sprintf("alicloud_mongodb_instance.%s", [name]),
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
