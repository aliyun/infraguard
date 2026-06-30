package infraguard.rules.aliyun.security_ecs_instance_security_group_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-ecs-instance-security-group-required",
    "severity": "high",
    "name": {
        "en": "ECS instance must attach a security group",
        "zh": "ECS 实例必须绑定安全组",
        "ja": "ECS インスタンスはセキュリティグループを設定する必要があります",
        "de": "ECS-Instanz muss eine Sicherheitsgruppe konfigurieren",
        "es": "La instancia ECS debe configurar un grupo de seguridad",
        "fr": "L'instance ECS doit configurer un groupe de sécurité",
        "pt": "A instância ECS deve configurar um grupo de segurança",
    },
    "description": {
        "en": "Checks ECS instance must attach a security group",
        "zh": "检查ECS 实例必须绑定安全组",
        "ja": "ECS インスタンスはセキュリティグループを設定する必要がありますことを確認します",
        "de": "Prüft, ob ECS-Instanz muss eine Sicherheitsgruppe konfigurieren.",
        "es": "Comprueba que la instancia ECS debe configurar un grupo de seguridad.",
        "fr": "Vérifie que l'instance ECS doit configurer un groupe de sécurité.",
        "pt": "Verifica se a instância ECS deve configurar um grupo de segurança.",
    },
    "reason": {
        "en": "ECS instance must attach a security group is not satisfied.",
        "zh": "ECS 实例必须绑定安全组未满足。",
        "ja": "ECS インスタンスはセキュリティグループを設定する必要がありますが満たされていません。",
        "de": "ECS-Instanz muss eine Sicherheitsgruppe konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que la instancia ECS debe configurar un grupo de seguridad.",
        "fr": "La condition suivante n'est pas satisfaite : l'instance ECS doit configurer un groupe de sécurité.",
        "pt": "A condição não foi satisfeita: a instância ECS deve configurar um grupo de segurança.",
    },
    "recommendation": {
        "en": "Configure SecurityGroupId on ALIYUN::ECS::Instance to satisfy the policy.",
        "zh": "请在 ALIYUN::ECS::Instance 上配置 SecurityGroupId 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::ECS::Instance に SecurityGroupId を設定してください。",
        "de": "Konfigurieren Sie SecurityGroupId für ALIYUN::ECS::Instance, um die Richtlinie zu erfüllen.",
        "es": "Configure SecurityGroupId en ALIYUN::ECS::Instance para cumplir la política.",
        "fr": "Configurez SecurityGroupId sur ALIYUN::ECS::Instance pour satisfaire la politique.",
        "pt": "Configure SecurityGroupId em ALIYUN::ECS::Instance para atender à política.",
    },
    "resource_types": ["ALIYUN::ECS::Instance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Instance")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "SecurityGroupId"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.has_property(resource, "SecurityGroupId")
}
