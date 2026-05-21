package infraguard.rules.terraform.firewall_asset_open_protect

import rego.v1

import data.infraguard.helpers.terraform as tf

rule_meta := {
	"id": "firewall-asset-open-protect",
	"severity": "medium",
	"name": {
		"en": "Cloud Firewall Asset Protection Enabled",
		"zh": "云防火墙资产开启保护",
		"ja": "クラウドファイアウォールアセット保護が有効",
		"de": "Cloud-Firewall-Asset-Schutz aktiviert",
		"es": "Protección de Activos del Firewall en la Nube Habilitada",
		"fr": "Protection des Actifs du Pare-feu Cloud Activée",
		"pt": "Proteção de Ativos do Firewall em Nuvem Habilitada"
	},
	"description": {
		"en": "Ensures assets are protected by Cloud Firewall control policies.",
		"zh": "确保资产已受云防火墙控制策略保护。",
		"ja": "アセットがクラウドファイアウォールによって保護されていることを確認します。",
		"de": "Stellt sicher, dass Assets durch Cloud Firewall geschützt sind.",
		"es": "Garantiza que los activos estén protegidos por el Firewall en la Nube.",
		"fr": "Garantit que les actifs sont protégés par le Pare-feu Cloud.",
		"pt": "Garante que os ativos estejam protegidos pelo Firewall em Nuvem."
	},
	"reason": {
		"en": "Unprotected assets are vulnerable to internet-based threats.",
		"zh": "未受保护的资产容易受到来自互联网的威胁。",
		"ja": "保護されていないアセットは、インターネットベースの脅威に対して脆弱です。",
		"de": "Ungeschützte Assets sind anfällig für internetbasierte Bedrohungen.",
		"es": "Los activos no protegidos son vulnerables a amenazas basadas en internet.",
		"fr": "Les actifs non protégés sont vulnérables aux menaces basées sur Internet.",
		"pt": "Ativos não protegidos são vulneráveis a ameaças baseadas em internet."
	},
	"recommendation": {
		"en": "Add alicloud_cloud_firewall_control_policy resources to enable protection.",
		"zh": "添加 alicloud_cloud_firewall_control_policy 资源以开启保护。",
		"ja": "ALIYUN::CLOUDFW::FwSwitch リソースを追加して、クラウドファイアウォール内のすべてのパブリック向けアセットの保護を有効にします。",
		"de": "Fügen Sie die Ressource ALIYUN::CLOUDFW::FwSwitch hinzu, um den Schutz für alle öffentlich zugänglichen Assets in Cloud Firewall zu aktivieren.",
		"es": "Agregue el recurso ALIYUN::CLOUDFW::FwSwitch para habilitar la protección para todos los activos públicos en el Firewall en la Nube.",
		"fr": "Ajoutez la ressource ALIYUN::CLOUDFW::FwSwitch pour activer la protection de tous les actifs publics dans le Pare-feu Cloud.",
		"pt": "Adicione o recurso ALIYUN::CLOUDFW::FwSwitch para habilitar a proteção para todos os ativos públicos no Firewall em Nuvem."
	},
	"resource_types": ["alicloud_cloud_firewall_control_policy"],
	"iac_type": "terraform"
}

has_resources_needing_protection if {
	some resource_type, _ in input.resources
	resource_type != "alicloud_cloud_firewall_control_policy"
}

deny contains violation if {
	has_resources_needing_protection
	not tf.has_resource_type("alicloud_cloud_firewall_control_policy")
	violation := {
		"id": rule_meta.id,
		"resource_id": "Global",
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}
