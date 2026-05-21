package infraguard.rules.aliyun.ecs_instance_no_public_and_anyip

import rego.v1

import data.infraguard.helpers

rule_meta := {
	"id": "ecs-instance-no-public-and-anyip",
	"severity": "medium",
	"name": {
		"en": "ECS Instance Should Not Bind Public IP or Allow Any IP Access",
		"zh": "ECS 实例禁止绑定公网地址和开放任意 ip",
		"ja": "ECS インスタンスはパブリック IP をバインドしないか、任意の IP アクセスを許可しない",
		"de": "ECS-Instanz sollte kein öffentliches IP binden oder Zugriff von beliebigen IPs zulassen",
		"es": "La Instancia ECS No Debe Vincular IP Público o Permitir Acceso de Cualquier IP",
		"fr": "L'Instance ECS Ne Doit Pas Lier d'IP Publique ou Autoriser l'Accès de N'importe Quelle IP",
		"pt": "Instância ECS Não Deve Vincular IP Público ou Permitir Acesso de Qualquer IP"
	},
	"description": {
		"en": "ECS instances should not directly bind IPv4 public IPs or Elastic IPs, and associated security groups should not expose 0.0.0.0/0. Compliant when no public IP is bound.",
		"zh": "ECS 实例没有直接绑定 IPv4 公网 IP 或弹性公网 IP，或关联的安全组未开放 0.0.0.0/0，视为合规。",
		"ja": "ECS インスタンスは IPv4 パブリック IP または Elastic IP を直接バインドせず、関連するセキュリティグループは 0.0.0.0/0 を公開しません。パブリック IP がバインドされていない場合は準拠と見なされます。",
		"de": "ECS-Instanzen sollten keine IPv4-öffentlichen IPs oder elastischen IPs direkt binden, und zugehörige Sicherheitsgruppen sollten 0.0.0.0/0 nicht freigeben. Konform, wenn keine öffentliche IP gebunden ist.",
		"es": "Las instancias ECS no deben vincular directamente IPs públicos IPv4 o IPs elásticos, y los grupos de seguridad asociados no deben exponer 0.0.0.0/0. Conforme cuando no se vincula ninguna IP pública.",
		"fr": "Les instances ECS ne doivent pas lier directement des IPs publiques IPv4 ou des IPs élastiques, et les groupes de sécurité associés ne doivent pas exposer 0.0.0.0/0. Conforme lorsqu'aucune IP publique n'est liée.",
		"pt": "Instâncias ECS não devem vincular diretamente IPs públicos IPv4 ou IPs elásticos, e os grupos de segurança associados não devem expor 0.0.0.0/0. Conforme quando nenhum IP público está vinculado."
	},
	"reason": {
		"en": "ECS instance has public IP allocation enabled or uses unrestricted internet bandwidth",
		"zh": "ECS 实例启用了公网 IP 分配或使用了不受限制的互联网带宽",
		"ja": "ECS インスタンスでパブリック IP 割り当てが有効になっているか、制限のないインターネット帯域幅を使用しています",
		"de": "ECS-Instanz hat öffentliche IP-Zuweisung aktiviert oder verwendet uneingeschränkte Internetbandbreite",
		"es": "La instancia ECS tiene asignación de IP pública habilitada o usa ancho de banda de internet sin restricciones",
		"fr": "L'instance ECS a l'allocation d'IP publique activée ou utilise une bande passante Internet sans restriction",
		"pt": "A instância ECS tem alocação de IP público habilitada ou usa largura de banda de internet sem restrições"
	},
	"recommendation": {
		"en": "Disable public IP allocation (AllocatePublicIP=false) and set InternetMaxBandwidthOut to 0. Use NAT Gateway or SLB for internet access instead.",
		"zh": "禁用公网 IP 分配(AllocatePublicIP=false)并将 InternetMaxBandwidthOut 设置为 0。改用 NAT 网关或 SLB 进行互联网访问。",
		"ja": "パブリック IP 割り当てを無効にし（AllocatePublicIP=false）、InternetMaxBandwidthOut を 0 に設定します。代わりに NAT ゲートウェイまたは SLB を使用してインターネットアクセスを行います。",
		"de": "Deaktivieren Sie die öffentliche IP-Zuweisung (AllocatePublicIP=false) und setzen Sie InternetMaxBandwidthOut auf 0. Verwenden Sie stattdessen NAT Gateway oder SLB für Internetzugriff.",
		"es": "Deshabilite la asignación de IP pública (AllocatePublicIP=false) y establezca InternetMaxBandwidthOut en 0. Use NAT Gateway o SLB para acceso a internet en su lugar.",
		"fr": "Désactivez l'allocation d'IP publique (AllocatePublicIP=false) et définissez InternetMaxBandwidthOut sur 0. Utilisez NAT Gateway ou SLB pour l'accès Internet à la place.",
		"pt": "Desabilite a alocação de IP público (AllocatePublicIP=false) e defina InternetMaxBandwidthOut como 0. Use NAT Gateway ou SLB para acesso à internet em vez disso."
	},
	"resource_types": ["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"]
}

# Check if instance has public IP allocated
has_public_ip(resource) if {
	print("public_ip", helpers.get_property(resource, "AllocatePublicIP", false))
	helpers.get_property(resource, "AllocatePublicIP", false) == true
}

# Check if instance has internet bandwidth (which implies public IP access)
has_internet_bandwidth(resource) if {
	helpers.has_property(resource, "InternetMaxBandwidthOut")
	resource.Properties.InternetMaxBandwidthOut > 0
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	has_public_ip(resource)
	result := {
		"id": rule_meta.id,
		"resource_id": name,
		"violation_path": ["Properties", "AllocatePublicIP"],
		"meta": {
			"severity": rule_meta.severity,
			"reason": rule_meta.reason,
			"recommendation": rule_meta.recommendation,
		},
	}
}

deny contains result if {
	some name, resource in helpers.resources_by_types(["ALIYUN::ECS::Instance", "ALIYUN::ECS::InstanceGroup"])
	has_internet_bandwidth(resource)
	not has_public_ip(resource) # Only report if not already reported by AllocatePublicIP check
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
