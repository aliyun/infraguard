---
title: Debugging von Richtlinien
---

# Debugging von Rego-Richtlinien

Es gibt zwei Möglichkeiten, Ihre Rego-Richtlinien zu debuggen: Verwenden von print-Anweisungen oder Verwenden des VSCode-Debuggers.

## Methode 1: Verwenden von Print-Anweisungen

### Grundlegende Verwendung

Fügen Sie `print()`-Anweisungen überall in Ihrer Rego-Richtlinie hinzu:

```rego
package infraguard.rules.aliyun.my_rule

import rego.v1
import data.infraguard.helpers

deny contains result if {
    print("Starting policy evaluation")
    
    some name, resource in helpers.resources_by_types(rule_meta.resource_types)
    print("Checking resource:", name)
    print("Resource type:", resource.Type)
    
    not is_compliant(resource)
    print("Found violation for resource:", name)
    
    result := {...}
}
```

### Ausgabeformat

Print-Anweisungen geben an stderr mit Dateispeicherort aus:

```
/path/to/policy.rego:42: Starting policy evaluation
/path/to/policy.rego:45: Checking resource: MyBucket
/path/to/policy.rego:46: Resource type: ALIYUN::OSS::Bucket
/path/to/policy.rego:49: Found violation for resource: MyBucket
```

### Häufige Verwendungsbeispiele

**Eingabedaten Inspizieren:**
```rego
print("Input keys:", object.keys(input))
print("Template version:", input.ROSTemplateFormatVersion)
print("Number of resources:", count(input.Resources))
```

**Ressourceniteration Debuggen:**
```rego
some name, resource in helpers.resources_by_types(rule_meta.resource_types)
print("Resource:", name)
print("Properties:", object.keys(resource.Properties))
```

**Bedingungen Prüfen:**
```rego
condition1 := some_check(resource)
print("Condition 1 result:", condition1)
```

**Variablen Inspizieren:**
```rego
property := helpers.get_property(resource, "SomeProperty", null)
print("Property value:", property)
print("Property type:", type_name(property))
```

## Methode 2: Verwenden des VSCode-Debuggers

VSCode bietet eine leistungsstärkere Debugging-Erfahrung mit Breakpoints, Variableninspektion und schrittweiser Ausführung.

### Voraussetzungen

1. **OPA Installieren**

   Laden Sie OPA von der offiziellen Website herunter und installieren Sie es:
   
   https://www.openpolicyagent.org/docs#1-download-opa

2. **Regal Installieren**

   Installieren Sie Regal für verbesserte Rego-Entwicklung:
   
   https://www.openpolicyagent.org/projects/regal#download-regal

3. **VSCode OPA-Erweiterung Installieren**

   Installieren Sie die offizielle OPA-Erweiterung aus dem VSCode-Marketplace:
   
   https://marketplace.visualstudio.com/items?itemName=tsandall.opa

### Einrichtungsschritte

1. **Testeingabe Vorbereiten**

   Erstellen Sie eine Datei namens `input.json` in Ihrem Richtlinienverzeichnis mit Ihren Testdaten:

   ```json
   {
     "ROSTemplateFormatVersion": "2015-09-01",
     "Resources": {
       "MyBucket": {
         "Type": "ALIYUN::OSS::Bucket",
         "Properties": {
           "BucketName": "test-bucket",
           "AccessControl": "private"
         }
       }
     }
   }
   ```

2. **Breakpoints Setzen**

   Öffnen Sie Ihre `.rego`-Richtliniendatei in VSCode und klicken Sie auf den linken Rand, um Breakpoints dort zu setzen, wo Sie die Ausführung anhalten möchten.

3. **Debugging Starten**

   - Drücken Sie `F5` oder gehen Sie zu Ausführen → Debugging Starten
   - Der Debugger hält an Ihren Breakpoints an
   - Sie können Variablen inspizieren, schrittweise durch den Code gehen und Ausdrücke auswerten

## Eine Methode Wählen

- **Print-Anweisungen**: Schnell und einfach, funktioniert in jeder Umgebung, nützlich für Produktions-Debugging
- **VSCode-Debugger**: Leistungsstärker, interaktives Debugging mit vollständiger Variableninspektion, besser für Entwicklung

Sie können beide Methoden zusammen verwenden: Verwenden Sie print-Anweisungen für schnelle Überprüfungen und den Debugger für tiefgreifende Untersuchungen.
