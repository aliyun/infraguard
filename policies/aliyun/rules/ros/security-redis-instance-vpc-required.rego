package infraguard.rules.aliyun.security_redis_instance_vpc_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-redis-instance-vpc-required",
    "severity": "high",
    "name": {
        "en": "Redis instance must run in VPC",
        "zh": "Redis 实例必须部署在 VPC 内",
        "ja": "Redis インスタンスは VPC を設定する必要があります",
        "de": "Redis-Instanz muss eine VPC konfigurieren",
        "es": "La instancia Redis debe configurar una VPC",
        "fr": "L'instance Redis doit configurer un VPC",
        "pt": "A instância Redis deve configurar uma VPC",
    },
    "description": {
        "en": "Checks Redis instance must run in VPC",
        "zh": "检查Redis 实例必须部署在 VPC 内",
        "ja": "Redis インスタンスは VPC を設定する必要がありますことを確認します",
        "de": "Prüft, ob Redis-Instanz muss eine VPC konfigurieren.",
        "es": "Comprueba que la instancia Redis debe configurar una VPC.",
        "fr": "Vérifie que l'instance Redis doit configurer un VPC.",
        "pt": "Verifica se a instância Redis deve configurar uma VPC.",
    },
    "reason": {
        "en": "Redis instance must run in VPC is not satisfied.",
        "zh": "Redis 实例必须部署在 VPC 内未满足。",
        "ja": "Redis インスタンスは VPC を設定する必要がありますが満たされていません。",
        "de": "Redis-Instanz muss eine VPC konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que la instancia Redis debe configurar una VPC.",
        "fr": "La condition suivante n'est pas satisfaite : l'instance Redis doit configurer un VPC.",
        "pt": "A condição não foi satisfeita: a instância Redis deve configurar uma VPC.",
    },
    "recommendation": {
        "en": "Configure VpcId on ALIYUN::REDIS::Instance to satisfy the policy.",
        "zh": "请在 ALIYUN::REDIS::Instance 上配置 VpcId 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::REDIS::Instance に VpcId を設定してください。",
        "de": "Konfigurieren Sie VpcId für ALIYUN::REDIS::Instance, um die Richtlinie zu erfüllen.",
        "es": "Configure VpcId en ALIYUN::REDIS::Instance para cumplir la política.",
        "fr": "Configurez VpcId sur ALIYUN::REDIS::Instance pour satisfaire la politique.",
        "pt": "Configure VpcId em ALIYUN::REDIS::Instance para atender à política.",
    },
    "resource_types": ["ALIYUN::REDIS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::REDIS::Instance")
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
