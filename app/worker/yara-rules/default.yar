/*
Demo YARA rules for the bundled worker scanner.

Notes:
  - These rules are intended as a starter pack for "payload hunting" (strings/patterns),
    not as a perfect malware classifier.
  - Only rules with a "_HIGH" suffix contribute to a "malicious" verdict by default
    (see YARA_VERDICT_MIN_SEVERITY in the worker).
  - Point the worker at a custom rules file via YARA_RULES_PATH.
*/

rule Demo_Malicious_Marker_HIGH
{
  meta:
    description = "Demo-only: matches an explicit marker string."
    reference = "Set SCAN_ENGINE=yara (or clamav,yara) and scan content containing this marker."

  strings:
    $marker = "aca-demo-malicious" nocase

  condition:
    $marker
}

rule EICAR_Test_String_HIGH
{
  meta:
    description = "Detects the standard EICAR antivirus test string (safe, for demos)."
    reference = "https://www.eicar.org/"

  strings:
    $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

  condition:
    $eicar
}

rule PowerShell_EncodedCommand_MEDIUM
{
  meta:
    description = "Potential PowerShell encoded command pattern (often used in droppers)."

  strings:
    $ps = /powershell(\.exe)?/ nocase
    $enc = /-(enc|encodedcommand)\b/ nocase
    $b64 = "FromBase64String" nocase

  condition:
    all of ($ps, $enc, $b64)
}

rule JavaScript_Obfuscation_Primitives_LOW
{
  meta:
    description = "Common JavaScript obfuscation primitives; informational signal."

  strings:
    $eval = "eval(" nocase
    $charcode = "fromCharCode" nocase
    $unescape = "unescape(" nocase
    $atob = "atob(" nocase
    $btoa = "btoa(" nocase

  condition:
    2 of them
}

rule HTML_Credential_Harvest_Form_LOW
{
  meta:
    description = "Heuristic-ish: HTML form that appears to collect passwords."

  strings:
    $form = "<form" nocase
    $password = /type\s*=\s*['"]password['"]/ nocase
    $action = "action=" nocase

  condition:
    all of ($form, $password, $action)
}

rule Filetype_PDF_INFO
{
  meta:
    description = "Payload looks like a PDF (not inherently malicious)."

  strings:
    $pdf = "%PDF-" ascii

  condition:
    $pdf at 0
}

rule Filetype_Windows_PE_INFO
{
  meta:
    description = "Payload looks like a Windows PE/EXE (not inherently malicious)."

  strings:
    $mz = "MZ" ascii

  condition:
    $mz at 0
}

rule Large_Base64_Blob_INFO
{
  meta:
    description = "Contains a large base64-ish blob; may indicate obfuscation or embedded data."

  strings:
    $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/

  condition:
    $b64
}

