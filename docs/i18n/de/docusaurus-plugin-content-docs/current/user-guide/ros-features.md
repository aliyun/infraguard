---
title: ROS-Funktionsunterstützung
---

# ROS-Funktionsunterstützung

InfraGuard unterstützt eine breite Palette von ROS (Resource Orchestration Service)-Vorlagenfunktionen für die statische Analyse und Validierung Ihres Infrastrukturcodes.

## Funktionen

InfraGuard unterstützt die folgenden ROS-Funktionen:

### String-Funktionen
- [`Fn::Join`](https://www.alibabacloud.com/help/en/ros/user-guide/function-join) - Verbindet Strings mit einem Trennzeichen
- [`Fn::Sub`](https://www.alibabacloud.com/help/en/ros/user-guide/function-sub) - Ersetzt Variablen in einem String
- [`Fn::Split`](https://www.alibabacloud.com/help/en/ros/user-guide/function-split) - Teilt einen String in eine Liste
- [`Fn::Replace`](https://www.alibabacloud.com/help/en/ros/user-guide/function-replace) - Ersetzt Strings im Text
- [`Fn::Str`](https://www.alibabacloud.com/help/en/ros/user-guide/function-str) - Konvertiert Werte zu Strings
- [`Fn::Indent`](https://www.alibabacloud.com/help/en/ros/user-guide/function-indent) - Rückt Text ein

### Kodierungsfunktionen
- [`Fn::Base64Encode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64encode) - Kodiert zu Base64
- [`Fn::Base64Decode`](https://www.alibabacloud.com/help/en/ros/user-guide/function-base64decode) - Dekodiert von Base64

### Listenfunktionen
- [`Fn::Select`](https://www.alibabacloud.com/help/en/ros/user-guide/function-select) - Wählt ein Element aus einer Liste
- [`Fn::Index`](https://www.alibabacloud.com/help/en/ros/user-guide/function-index) - Findet den Index eines Elements
- [`Fn::Length`](https://www.alibabacloud.com/help/en/ros/user-guide/function-length) - Gibt die Länge einer Liste oder eines Strings zurück
- [`Fn::ListMerge`](https://www.alibabacloud.com/help/en/ros/user-guide/function-listmerge) - Führt mehrere Listen zusammen

### Map-Funktionen
- [`Fn::FindInMap`](https://www.alibabacloud.com/help/en/ros/user-guide/function-findinmap) - Ruft Werte aus einer Zuordnung ab
- [`Fn::SelectMapList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-selectmaplist) - Wählt Werte aus einer Liste von Maps aus
- [`Fn::MergeMapToList`](https://www.alibabacloud.com/help/en/ros/user-guide/function-mergemaptolist) - Führt Maps in eine Liste zusammen

### Mathematische Funktionen
- [`Fn::Add`](https://www.alibabacloud.com/help/en/ros/user-guide/function-add) - Addiert Zahlen
- [`Fn::Avg`](https://www.alibabacloud.com/help/en/ros/user-guide/function-avg) - Berechnet den Durchschnitt
- [`Fn::Max`](https://www.alibabacloud.com/help/en/ros/user-guide/function-max) - Gibt den Maximalwert zurück
- [`Fn::Min`](https://www.alibabacloud.com/help/en/ros/user-guide/function-min) - Gibt den Minimalwert zurück
- [`Fn::Calculate`](https://www.alibabacloud.com/help/en/ros/user-guide/function-calculate) - Wertet mathematische Ausdrücke aus

### Bedingte Funktionen
- [`Fn::If`](https://www.alibabacloud.com/help/en/ros/user-guide/function-if) - Gibt Werte basierend auf Bedingungen zurück
- [`Fn::Equals`](https://www.alibabacloud.com/help/en/ros/user-guide/function-equals) - Vergleicht zwei Werte
- [`Fn::And`](https://www.alibabacloud.com/help/en/ros/user-guide/function-and) - Logisches UND
- [`Fn::Or`](https://www.alibabacloud.com/help/en/ros/user-guide/function-or) - Logisches ODER
- [`Fn::Not`](https://www.alibabacloud.com/help/en/ros/user-guide/function-not) - Logisches NICHT
- [`Fn::Contains`](https://www.alibabacloud.com/help/en/ros/user-guide/function-contains) - Prüft, ob ein Wert in einer Liste ist
- [`Fn::Any`](https://www.alibabacloud.com/help/en/ros/user-guide/function-any) - Prüft, ob eine Bedingung wahr ist
- [`Fn::EachMemberIn`](https://www.alibabacloud.com/help/en/ros/user-guide/function-eachmemberin) - Prüft, ob alle Elemente in einer anderen Liste sind
- [`Fn::MatchPattern`](https://www.alibabacloud.com/help/en/ros/user-guide/function-matchpattern) - Entspricht einem Muster

### Hilfsfunktionen
- [`Fn::GetJsonValue`](https://www.alibabacloud.com/help/en/ros/user-guide/function-getjsonvalue) - Extrahiert Werte aus JSON
- [`Ref`](https://www.alibabacloud.com/help/en/ros/user-guide/ref) - Verweist auf Parameter und Ressourcen

## Bedingungen

InfraGuard unterstützt vollständig die Funktion [ROS Conditions](https://www.alibabacloud.com/help/ros/user-guide/conditions), einschließlich:

- **Bedingungsdefinition** - Definieren Sie Bedingungen im Abschnitt `Conditions`
- **Bedingungsfunktionen** - Verwenden Sie `Fn::Equals`, `Fn::And`, `Fn::Or`, `Fn::Not`, `Fn::If` in Bedingungen
- **Bedingungsreferenzen** - Verweisen Sie auf Bedingungen in Ressourcen und Ausgaben
- **Abhängigkeitsauflösung** - Löst automatisch Bedingungsabhängigkeiten auf

## YAML-Kurzsyntax

InfraGuard unterstützt die YAML-Kurzsyntax (Tag-Notation) für ROS-Funktionen:

- `!Ref` - Kurzform von `Ref`
- `!GetAtt` - Kurzform von `Fn::GetAtt`
- Alle anderen `Fn::*`-Funktionen können als `!FunctionName` geschrieben werden

Der YAML-Parser konvertiert diese Kurzformen automatisch in ihre Standard-Map-Darstellung beim Laden der Vorlage.

## Nicht Unterstützte Funktionen

InfraGuard konzentriert sich auf statische Analyse und unterstützt derzeit die folgenden Funktionen im statischen Modus nicht:

### Laufzeitfunktionen
- `Fn::GetAtt` - Erfordert tatsächliche Ressourcenerstellung, um Attribute abzurufen
- `Fn::GetAZs` - Erfordert Laufzeitabfrage an den Cloud-Anbieter
- `Fn::GetStackOutput` - Erfordert Zugriff auf andere Stack-Ausgaben

### Vorlagenabschnitte
- `Locals` - Lokale Variablendefinitionen
- `Transform` - Vorlagentransformationen und Makros
- `Rules` - Vorlagenvalidierungsregeln
- `Mappings` - Statische Wertzuordnungen (nicht auf Richtlinienverstöße analysiert)

### Spezielle Referenzen
- Pseudo-Parameter (z. B. `ALIYUN::StackId`, `ALIYUN::Region`, etc.) - Vom System bereitgestellte Parameter

Diese Funktionen werden unverändert in der Analyseausgabe erhalten, ohne Auswertung oder Validierung bei Verwendung des statischen Modus.

> **Astuce** : Pour les modèles utilisant des fonctionnalités non supportées par l'analyse statique (telles que `Fn::GetAtt`, `Fn::GetAZs`, etc.), nous recommandons d'utiliser `--mode preview` pour tirer parti de l'API ROS PreviewStack pour une analyse plus précise. Le mode preview évalue les modèles avec le contexte réel du fournisseur de cloud, permettant le support des fonctions d'exécution et d'autres fonctionnalités dynamiques.

## Ressources Connexes

- [Structure de Modèle ROS](https://www.alibabacloud.com/help/en/ros/user-guide/template-structure)
- [Fonctions ROS](https://www.alibabacloud.com/help/en/ros/user-guide/functions)
- [Conditions ROS](https://www.alibabacloud.com/help/en/ros/user-guide/conditions)
