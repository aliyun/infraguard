package infraguard.rules.aliyun.ess_scaling_configuration_enabled_internet_check

import rego.v1

import data.infraguard.helpers

# Rule metadata
rule_meta := {
	"id": "ess-scaling-configuration-enabled-internet-check",
	"severity": "medium",
	"name": {
		"en": "ESS Scaling Configuration Internet Access Check",
		"zh": "ESS 伸缩配置公网访问检测",
		"ja": "ESS スケーリング設定のインターネットアクセチェック",
		"de": "ESS-Skalierungskonfiguration Internetzugriffsprüfung",
		"es": "Verificación de Acceso a Internet de Configuración de Escalado ESS",
		"fr": "Vérification de l'Accès Internet de la Configuration de Mise à l'Échelle ESS",
		"pt": "Verificação de Acesso à Internet da Configuração de Escalonamento ESS"
	},
	"description": {
		"en": "Ensures that ESS scaling configurations do not enable public IP addresses for instances unless necessary.",
		"zh": "确保 ESS 伸缩配置未为实例开启公网 IP 地址，除非必要。",
		"ja": "ESS スケーリング設定が、必要でない限りインスタンスにパブリック IP アドレスを有効にしないことを確認します。",
		"de": "Stellt sicher, dass ESS-Skalierungskonfigurationen keine öffentlichen IP-Adressen für Instanzen aktivieren, es sei denn, es ist notwendig.",
		"es": "Garantiza que las configuraciones de escalado ESS no habiliten direcciones IP públicas para instancias a menos que sea necesario.",
		"fr": "Garantit que les configurations de mise à l'échelle ESS n'activent pas d'adresses IP publiques pour les instances sauf si nécessaire.",
		"pt": "Garante que as configurações de escalonamento ESS não habilitem endereços IP públicos para instâncias, a menos que seja necessário."
	},
	"reason": {
		"en": "Enabling public IPs for all instances in a scaling group increases the attack surface.",
		"zh": "为伸缩组中的所有实例开启公网 IP 会增加攻击面。",
		"ja": "スケーリンググループ内のすべてのインスタンスにパブリック IP を有効にすると、攻撃面が増加します。",
		"de": "Das Aktivieren öffentlicher IPs für alle Instanzen in einer Skalierungsgruppe erhöht die Angriffsfläche.",
		"es": "Habilitar IPs públicas para todas las instancias en un grupo de escalado aumenta la superficie de ataque.",
		"fr": "Activer les IP publiques pour toutes les instances d'un groupe de mise à l'échelle augmente la surface d'attaque.",
		"pt": "Habilitar IPs públicos para todas as instâncias em um grupo de escalonamento aumenta a superfície de ataque."
	},
	"recommendation": {
		"en": "Use internal IPs and a NAT gateway or SLB for internet access instead of public IPs on each instance.",
		"zh": "使用内网 IP 和 NAT 网关或 SLB 进行公网访问，而不是在每个实例上使用公网 IP。",
		"ja": "各インスタンスでパブリック IP を使用する代わりに、内部 IP と NAT ゲートウェイまたは SLB を使用してインターネットアクセスを行います。",
		"de": "Verwenden Sie interne IPs und ein NAT-Gateway oder SLB für den Internetzugriff, anstatt öffentliche IPs auf jeder Instanz zu verwenden.",
		"es": "Use IPs internas y una puerta de enlace NAT o SLB para acceso a internet en lugar de IPs públicas en cada instancia.",
		"fr": "Utilisez des IP internes et une passerelle NAT ou SLB pour l'accès Internet au lieu d'IP publiques sur chaque instance.",
		"pt": "Use IPs internos e um gateway NAT ou SLB para acesso à internet em vez de IPs públicos em cada instância."
	},
	"resource_types": ["ALIYUN::ESS::ScalingConfiguration"]
}

deny contains result if {
	some name, resource in helpers.resources_by_type("ALIYUN::ESS::ScalingConfiguration")
	helpers.get_property(resource, "InternetMaxBandwidthOut", 0) > 0
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "InternetMaxBandwidthOut"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
