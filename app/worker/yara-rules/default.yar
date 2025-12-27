/*
Demo YARA rules for the bundled worker scanner.

Notes:
  - Keep these rules intentionally conservative to avoid false positives in demos.
  - Point the worker at a custom rules file via YARA_RULES_PATH.
*/

rule ACA_UrlScanner_Demo_Malicious_Marker
{
  meta:
    description = "Demo-only: matches an explicit marker string."
    reference = "Set SCAN_ENGINE=yara (or clamav,yara) and scan content containing this marker."

  strings:
    $marker = "aca-demo-malicious" nocase

  condition:
    $marker
}

