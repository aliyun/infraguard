# Resource Idle Detection Best Practice Pack
# Detect common cloud resources that are idle after purchase, involving EIP, shared bandwidth, VPC, VPN, etc.
# Idle resources lead to cost waste and should be identified and managed in time.
package infraguard.packs.aliyun.resource_idle_detection_best_practice

import rego.v1

# Pack metadata with i18n support
pack_meta := {
	"id": "resource-idle-detection-best-practice",
	"name": {
		"en": "Resource Idle Detection Best Practice",
		"zh": "资源空闲检测最佳实践",
		"ja": "リソースアイドル検出のベストプラクティス",
		"de": "Ressourcen-Leerlauf-Erkennung Best Practices",
		"es": "Mejores Prácticas de Detección de Recursos Inactivos",
		"fr": "Meilleures Pratiques de Détection des Ressources Inactives",
		"pt": "Melhores Práticas de Detecção de Recursos Inativos",
	},
	"description": {
		"en": "Detect common cloud resources that are idle after purchase, involving EIP, shared bandwidth, VPC, VPN and other cloud products. Idle resources lead to enterprise cost waste and should be identified and managed in time.",
		"zh": "检测常见的云资源在购买以后是否被闲置，涉及弹性公网 IP、共享带宽、VPC、VPN 等云产品。资源购买后未启用会导致企业成本的浪费，建议及时发现并治理。",
		"ja": "購入後にアイドル状態になっている一般的なクラウドリソースを検出します。EIP、共有帯域幅、VPC、VPN などのクラウド製品が含まれます。アイドルリソースは企業のコスト浪費につながるため、適時に特定して管理する必要があります。",
		"de": "Erkennung gängiger Cloud-Ressourcen, die nach dem Kauf im Leerlauf sind, einschließlich EIP, gemeinsam genutzter Bandbreite, VPC, VPN und anderen Cloud-Produkten. Leerlaufende Ressourcen führen zu Unternehmenskostenverschwendung und sollten rechtzeitig identifiziert und verwaltet werden.",
		"es": "Detecta recursos en la nube comunes que están inactivos después de la compra, involucrando EIP, ancho de banda compartido, VPC, VPN y otros productos en la nube. Los recursos inactivos conducen al desperdicio de costos empresariales y deben identificarse y gestionarse a tiempo.",
		"fr": "Détecte les ressources cloud courantes qui sont inactives après l'achat, impliquant EIP, bande passante partagée, VPC, VPN et d'autres produits cloud. Les ressources inactives entraînent un gaspillage des coûts d'entreprise et doivent être identifiées et gérées à temps.",
		"pt": "Detecta recursos em nuvem comuns que estão inativos após a compra, envolvendo EIP, largura de banda compartilhada, VPC, VPN e outros produtos em nuvem. Recursos inativos levam ao desperdício de custos empresariais e devem ser identificados e gerenciados a tempo.",
	},
	"rules": ["ecs-disk-idle-check"], # "cr-instance-idle-check", # "alb-instance-idle-check", # "cbwp-bandwidth-package-idle-check",
	# "ecs-instance-status-no-stopped",  # Commented: ROS ECS::Instance does not support Status property
	# "eip-idle-check",
	# "nas-filesystem-idle-check",
	# "internet-natgateway-idle-check",
	# "intranet-natgateway-idle-check",
	# "slb-instance-idle-check",
	# "vpn-gateway-idle-check"

}
