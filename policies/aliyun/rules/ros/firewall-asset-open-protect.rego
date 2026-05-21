package infraguard.rules.aliyun.firewall_asset_open_protect

import data.infraguard.helpers
import rego.v1

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
		"en": "Ensures assets are protected by Cloud Firewall.",
		"zh": "确保资产已受云防火墙保护。",
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
		"en": "Add ALIYUN::CLOUDFW::FwSwitch resource to enable protection for all public-facing assets in Cloud Firewall.",
		"zh": "添加 ALIYUN::CLOUDFW::FwSwitch 资源以在云防火墙中为所有面向公网的资产开启保护。",
		"ja": "ALIYUN::CLOUDFW::FwSwitch リソースを追加して、クラウドファイアウォール内のすべてのパブリック向けアセットの保護を有効にします。",
		"de": "Fügen Sie die Ressource ALIYUN::CLOUDFW::FwSwitch hinzu, um den Schutz für alle öffentlich zugänglichen Assets in Cloud Firewall zu aktivieren.",
		"es": "Agregue el recurso ALIYUN::CLOUDFW::FwSwitch para habilitar la protección para todos los activos públicos en el Firewall en la Nube.",
		"fr": "Ajoutez la ressource ALIYUN::CLOUDFW::FwSwitch pour activer la protection de tous les actifs publics dans le Pare-feu Cloud.",
		"pt": "Adicione o recurso ALIYUN::CLOUDFW::FwSwitch para habilitar a proteção para todos os ativos públicos no Firewall em Nuvem."
	},
	"resource_types": ["ALIYUN::CLOUDFW::FwSwitch"]
}

# ALIYUN::CLOUDFW::FwSwitch resource existence means protection is enabled
# This rule only checks if FwSwitch resources exist in the template
# If no FwSwitch resource exists, we cannot verify protection at template level
# This is a conceptual check that requires runtime verification
# We only flag violations if there are other resources that might need protection
# but no FwSwitch resources exist

# Check if template has any resources that might need firewall protection
# Exclude dummy resources like ALIYUN::ROS::WaitConditionHandle
has_resources_needing_protection if {
	some name, resource in input.Resources
	resource.Type != "ALIYUN::ROS::WaitConditionHandle"
}

# Only flag violation if there are resources but no FwSwitch
deny contains result if {
	has_resources_needing_protection
	count(helpers.resources_by_type("ALIYUN::CLOUDFW::FwSwitch")) == 0
	result := {
		"id": rule_meta.id,
		"resource_id": "",
		"violation_path": ["Resources"],
		"meta": {"severity": rule_meta.severity, "reason": rule_meta.reason, "recommendation": rule_meta.recommendation},
	}
}
