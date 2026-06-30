package infraguard.rules.aliyun.security_ecs_instance_vpc_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-ecs-instance-vpc-required",
    "severity": "high",
    "name": {
        "en": "ECS instance must run in VPC",
        "zh": "ECS 实例必须部署在 VPC 内",
        "ja": "ECS インスタンスは VPC を設定する必要があります",
        "de": "ECS-Instanz muss eine VPC konfigurieren",
        "es": "La instancia ECS debe configurar una VPC",
        "fr": "L'instance ECS doit configurer un VPC",
        "pt": "A instância ECS deve configurar uma VPC",
    },
    "description": {
        "en": "Checks ECS instance must run in VPC",
        "zh": "检查ECS 实例必须部署在 VPC 内",
        "ja": "ECS インスタンスは VPC を設定する必要がありますことを確認します",
        "de": "Prüft, ob ECS-Instanz muss eine VPC konfigurieren.",
        "es": "Comprueba que la instancia ECS debe configurar una VPC.",
        "fr": "Vérifie que l'instance ECS doit configurer un VPC.",
        "pt": "Verifica se a instância ECS deve configurar uma VPC.",
    },
    "reason": {
        "en": "ECS instance must run in VPC is not satisfied.",
        "zh": "ECS 实例必须部署在 VPC 内未满足。",
        "ja": "ECS インスタンスは VPC を設定する必要がありますが満たされていません。",
        "de": "ECS-Instanz muss eine VPC konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que la instancia ECS debe configurar una VPC.",
        "fr": "La condition suivante n'est pas satisfaite : l'instance ECS doit configurer un VPC.",
        "pt": "A condição não foi satisfeita: a instância ECS deve configurar uma VPC.",
    },
    "recommendation": {
        "en": "Configure VpcId on ALIYUN::ECS::Instance to satisfy the policy.",
        "zh": "请在 ALIYUN::ECS::Instance 上配置 VpcId 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::ECS::Instance に VpcId を設定してください。",
        "de": "Konfigurieren Sie VpcId für ALIYUN::ECS::Instance, um die Richtlinie zu erfüllen.",
        "es": "Configure VpcId en ALIYUN::ECS::Instance para cumplir la política.",
        "fr": "Configurez VpcId sur ALIYUN::ECS::Instance pour satisfaire la politique.",
        "pt": "Configure VpcId em ALIYUN::ECS::Instance para atender à política.",
    },
    "resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "VpcId"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.has_property(resource, "VpcId")
}
