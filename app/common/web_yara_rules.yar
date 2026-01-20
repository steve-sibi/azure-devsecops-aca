/*
Web analysis YARA rules.

These rules power the lightweight "web security analysis" heuristics (JS sniffing).
They are not intended to be a full malware classifier.
*/

rule Web_Suspicious_JS_MEDIUM
{
  meta:
    description = "Suspicious JavaScript indicators (strong keywords or multi-signal obfuscation)."

  strings:
    /* Strong indicators (1 match is enough) */
    $activex = "ActiveXObject" nocase
    $wscript = "wscript." nocase
    $powershell = "powershell" nocase
    $cmd = "cmd.exe" nocase
    $mshta = "mshta" nocase
    $rundll32 = "rundll32" nocase
    $regsvr32 = "regsvr32" nocase

    /* Weaker indicators (require combination) */
    $document_write = "document.write(" nocase
    $unescape = "unescape(" nocase
    $fromcharcode = "fromCharCode" nocase
    $atob = "atob(" nocase
    $eval = "eval(" nocase
    $new_function = /new\s+function\s*\(/ nocase

  condition:
    any of ($activex, $wscript, $powershell, $cmd, $mshta, $rundll32, $regsvr32)
    or (2 of ($document_write, $unescape, $fromcharcode, $atob, $eval, $new_function))
}

rule Web_Fingerprinting_INFO
{
  meta:
    description = "Fingerprinting-related APIs and libraries."

  strings:
    /* Common libs */
    $fpjs = "fingerprintjs" nocase
    $fpmin = "fp.min.js" nocase

    /* Browser fingerprinting primitives */
    $audiocontext = "AudioContext" nocase
    $offlineaudiocontext = "OfflineAudioContext" nocase
    $webgl = "WebGLRenderingContext" nocase
    $getimagedata = "getImageData" nocase
    $todataurl = "toDataURL" nocase
    $nav_plugins = "navigator.plugins" nocase
    $hw = "navigator.hardwareConcurrency" nocase
    $mem = "navigator.deviceMemory" nocase
    $canvas = "canvas" nocase

  condition:
    any of ($fpjs, $fpmin) or (2 of ($audiocontext, $offlineaudiocontext, $webgl, $getimagedata, $todataurl, $nav_plugins, $hw, $mem, $canvas))
}

rule Web_Eval_Usage_INFO
{
  meta:
    description = "Use of eval/new Function."

  strings:
    $eval = "eval(" nocase
    $new_function = /new\s+function\s*\(/ nocase

  condition:
    any of them
}

rule Web_InnerHTML_Usage_INFO
{
  meta:
    description = "Use of innerHTML/outerHTML."

  strings:
    $inner = "innerHTML" nocase
    $outer = "outerHTML" nocase

  condition:
    any of them
}

rule Web_Tracking_Inline_INFO
{
  meta:
    description = "Inline tracking calls (gtag/ga/fbq/dataLayer)."

  strings:
    $gtag = "gtag(" nocase
    $ga = "ga(" nocase
    $fbq = "fbq(" nocase
    $datalayer = "dataLayer" nocase

  condition:
    any of them
}

