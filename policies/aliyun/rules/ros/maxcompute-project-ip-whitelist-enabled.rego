package infraguard.rules.aliyun.maxcompute_project_ip_whitelist_enabled

import data.infraguard.helpers
import rego.v1

rule_meta := {
	"id": "maxcompute-project-ip-whitelist-enabled",
	"severity": "high",
	"name": {
		"en": "MaxCompute Project IP Whitelist Enabled",
		"zh": "MaxCompute 项目开启 IP 白名单",
		"ja": "MaxCompute プロジェクトの IP ホワイトリストが有効",
		"de": "MaxCompute-Projekt IP-Whitelist aktiviert",
		"es": "Lista Blanca de IP del Proyecto MaxCompute Habilitada",
		"fr": "Liste Blanche IP du Projet MaxCompute Activée",
		"pt": "Lista Branca de IP do Projeto MaxCompute Habilitada"
	},
	"description": {
		"en": "Ensures MaxCompute projects have an IP whitelist configured to restrict access.",
		"zh": "确保 MaxCompute 项目配置了 IP 白名单以限制访问。",
		"ja": "MaxCompute プロジェクトにアクセスを制限する IP ホワイトリストが設定されていることを確認します。",
		"de": "Stellt sicher, dass MaxCompute-Projekte eine IP-Whitelist konfiguriert haben, um den Zugriff einzuschränken.",
		"es": "Garantiza que los proyectos MaxCompute tengan una lista blanca de IP configurada para restringir el acceso.",
		"fr": "Garantit que les projets MaxCompute ont une liste blanche IP configurée pour restreindre l'accès.",
		"pt": "Garante que os projetos MaxCompute tenham uma lista branca de IP configurada para restringir o acesso."
	},
	"reason": {
		"en": "Restricting access to trusted IPs prevents unauthorized data access over the network.",
		"zh": "限制可信 IP 访问可防止网络上的非授权数据访问。",
		"ja": "信頼できる IP へのアクセスを制限することで、ネットワーク経由の不正なデータアクセスを防ぎます。",
		"de": "Die Einschränkung des Zugriffs auf vertrauenswürdige IPs verhindert nicht autorisierten Datenzugriff über das Netzwerk.",
		"es": "Restringir el acceso a IPs de confianza previene el acceso no autorizado a datos a través de la red.",
		"fr": "Restreindre l'accès aux IP de confiance empêche l'accès non autorisé aux données sur le réseau.",
		"pt": "Restringir o acesso a IPs confiáveis impede o acesso não autorizado a dados pela rede."
	},
	"recommendation": {
		"en": "Configure the IP whitelist for the MaxCompute project.",
		"zh": "为 MaxCompute 项目配置 IP 白名单。",
		"ja": "MaxCompute プロジェクトに IP ホワイトリストを設定します。",
		"de": "Konfigurieren Sie die IP-Whitelist für das MaxCompute-Projekt.",
		"es": "Configure la lista blanca de IP para el proyecto MaxCompute.",
		"fr": "Configurez la liste blanche IP pour le projet MaxCompute.",
		"pt": "Configure a lista branca de IP para o projeto MaxCompute."
	},
	"resource_types": ["ALIYUN::MaxCompute::Project"]
}

is_compliant(resource) if {
	# Check for a property like 'IpWhiteList' in ROS
	helpers.has_property(resource, "IpWhiteList")
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::MaxCompute::Project")
	not is_compliant(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
