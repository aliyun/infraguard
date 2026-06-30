package infraguard.rules.aliyun.security_ecs_disk_encrypted

import rego.v1
import data.infraguard.helpers

rule_meta := {
    "id": "security-ecs-disk-encrypted",
    "severity": "high",
    "name": {
        "en": "ECS disk must enable encryption",
        "zh": "ECS 云盘必须启用加密",
        "ja": "ECS ディスクは暗号化を有効にする必要があります",
        "de": "ECS-Datenträger muss Verschlüsselung aktivieren",
        "es": "El disco ECS debe habilitar el cifrado",
        "fr": "Le disque ECS doit activer le chiffrement",
        "pt": "O disco ECS deve habilitar criptografia",
    },
    "description": {
        "en": "Checks ECS disk must enable encryption",
        "zh": "检查ECS 云盘必须启用加密",
        "ja": "ECS ディスクは暗号化を有効にする必要がありますことを確認します",
        "de": "Prüft, ob ECS-Datenträger muss Verschlüsselung aktivieren.",
        "es": "Comprueba que el disco ECS debe habilitar el cifrado.",
        "fr": "Vérifie que le disque ECS doit activer le chiffrement.",
        "pt": "Verifica se o disco ECS deve habilitar criptografia.",
    },
    "reason": {
        "en": "ECS disk must enable encryption is not satisfied.",
        "zh": "ECS 云盘必须启用加密未满足。",
        "ja": "ECS ディスクは暗号化を有効にする必要がありますが満たされていません。",
        "de": "ECS-Datenträger muss Verschlüsselung aktivieren ist nicht erfüllt.",
        "es": "No se cumple que el disco ECS debe habilitar el cifrado.",
        "fr": "La condition suivante n'est pas satisfaite : le disque ECS doit activer le chiffrement.",
        "pt": "A condição não foi satisfeita: o disco ECS deve habilitar criptografia.",
    },
    "recommendation": {
        "en": "Configure Encrypted on ALIYUN::ECS::Disk to satisfy the policy.",
        "zh": "请在 ALIYUN::ECS::Disk 上配置 Encrypted 以满足策略。",
        "ja": "ポリシーを満たすには、ALIYUN::ECS::Disk に Encrypted を設定してください。",
        "de": "Konfigurieren Sie Encrypted für ALIYUN::ECS::Disk, um die Richtlinie zu erfüllen.",
        "es": "Configure Encrypted en ALIYUN::ECS::Disk para cumplir la política.",
        "fr": "Configurez Encrypted sur ALIYUN::ECS::Disk pour satisfaire la politique.",
        "pt": "Configure Encrypted em ALIYUN::ECS::Disk para atender à política.",
    },
    "resource_types": ["ALIYUN::ECS::Disk"],
}

deny contains result if {
    some name, resource in helpers.resources_by_type("ALIYUN::ECS::Disk")
    not is_compliant(resource)
    result := {
        "id": rule_meta.id,
        "resource_id": name,
        "violation_path": ["Properties", "Encrypted"],
        "meta": {
            "severity": rule_meta.severity,
            "reason": rule_meta.reason,
            "recommendation": rule_meta.recommendation,
        },
    }
}

is_compliant(resource) if {
    helpers.get_property(resource, "Encrypted", false) == true
}
