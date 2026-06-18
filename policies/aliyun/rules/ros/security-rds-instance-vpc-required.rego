package infraguard.rules.aliyun.security_rds_instance_vpc_required

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-rds-instance-vpc-required",
    "severity": "high",
    "name": {
        "en": "RDS instance must run in VPC",
        "zh": "RDS 实例必须部署在 VPC 内",
        "ja": "RDS インスタンスは VPC を設定する必要があります",
        "de": "RDS-Instanz muss eine VPC konfigurieren",
        "es": "La instancia RDS debe configurar una VPC",
        "fr": "L'instance RDS doit configurer un VPC",
        "pt": "A instância RDS deve configurar uma VPC",
    },
    "description": {
        "en": "Checks RDS instance must run in VPC",
        "zh": "检查RDS 实例必须部署在 VPC 内",
        "ja": "RDS インスタンスは VPC を設定する必要がありますことを確認します",
        "de": "Prüft, ob RDS-Instanz muss eine VPC konfigurieren.",
        "es": "Comprueba que la instancia RDS debe configurar una VPC.",
        "fr": "Vérifie que l'instance RDS doit configurer un VPC.",
        "pt": "Verifica se a instância RDS deve configurar uma VPC.",
    },
    "reason": {
        "en": "RDS instance must run in VPC is not satisfied.",
        "zh": "RDS 实例必须部署在 VPC 内未满足。",
        "ja": "RDS インスタンスは VPC を設定する必要がありますが満たされていません。",
        "de": "RDS-Instanz muss eine VPC konfigurieren ist nicht erfüllt.",
        "es": "No se cumple que la instancia RDS debe configurar una VPC.",
        "fr": "La condition suivante n'est pas satisfaite : l'instance RDS doit configurer un VPC.",
        "pt": "A condição não foi satisfeita: a instância RDS deve configurar uma VPC.",
    },
    "recommendation": {
        "en": "Configure VpcId on ALIYUN::RDS::DBInstance to satisfy the policy.",
        "zh": "请在 ALIYUN::RDS::DBInstance 上配置 VpcId 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::RDS::DBInstance に VpcId を設定してください。",
        "de": "Konfigurieren Sie VpcId für ALIYUN::RDS::DBInstance, um die Richtlinie zu erfüllen.",
        "es": "Configure VpcId en ALIYUN::RDS::DBInstance para cumplir la política.",
        "fr": "Configurez VpcId sur ALIYUN::RDS::DBInstance pour satisfaire la politique.",
        "pt": "Configure VpcId em ALIYUN::RDS::DBInstance para atender à política.",
    },
    "resource_types": ["ALIYUN::RDS::DBInstance"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::RDS::DBInstance")
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
