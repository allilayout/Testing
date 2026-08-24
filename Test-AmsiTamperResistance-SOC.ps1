# Test-AmsiTamperResistance-SOC.ps1
# ASPAT hardening-validation probe: are the PRIMITIVES an AMSI bypass needs
# reachable in this engine? READ-ONLY, fully benign.
#
# It does NOT bypass AMSI, does NOT touch AmsiUtils/amsiInitFailed, writes no
# memory, and carries no bypass signatures - so it runs even where the classic
# bypass is (correctly) blocked. It only measures capability:
#
#   * Add-Type                         -> can attacker compile arbitrary code / P-Invoke?
#   * [Marshal]::* method invocation   -> can attacker call the memory APIs (MarshalCopy)?
#
# EVERY AMSI-patch bypass depends on BOTH. If both are reachable, the engine is
# bypassable regardless of which signature the AV happens to catch today. If
# both are blocked (Constrained Language Mode), no AMSI-patch bypass can run.
#
# Run before AND after enforcing CLM via WDAC to show the delta. Authorized host only.

$ErrorActionPreference = 'Stop'
$marker = "ASPAT-SOC-TEST-$([guid]::NewGuid().ToString('N').Substring(0,8))"
Write-Host "[*] $marker  AMSI bypass-primitive reachability probe (READ-ONLY)" -ForegroundColor Cyan

$lang = $ExecutionContext.SessionState.LanguageMode
Write-Host "    LanguageMode : $lang" -ForegroundColor Yellow

$addTypeOpen = $false
$marshalOpen = $false

# --- PRIMITIVE 1: Add-Type (arbitrary compile -> the P/Invoke gateway) ---
# CLM blocks Add-Type entirely. FullLanguage allows it.
try {
    Add-Type -TypeDefinition 'public class AspatClmProbe { public static int Ok(){ return 1; } }' -ErrorAction Stop
    $null = [AspatClmProbe]::Ok()
    $addTypeOpen = $true
    Write-Host "    [PRIMITIVE-1] Add-Type (compile / P-Invoke): AVAILABLE" -ForegroundColor Magenta
} catch {
    Write-Host "    [PRIMITIVE-1] Add-Type blocked -> $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Green
}

# --- PRIMITIVE 2: arbitrary .NET method invocation on a non-core type ---
# [Marshal] is the exact class memory-patch bypasses use (MarshalCopy). In CLM,
# invoking methods on non-core types throws. We call a harmless, read-only member.
try {
    $sz = [System.Runtime.InteropServices.Marshal]::SizeOf([type][int])
    if ($sz -gt 0) {
        $marshalOpen = $true
        Write-Host "    [PRIMITIVE-2] [Marshal]::* method invocation: AVAILABLE (SizeOf(int)=$sz)" -ForegroundColor Magenta
    }
} catch {
    Write-Host "    [PRIMITIVE-2] [Marshal]::* blocked -> $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Green
}

Write-Host ""
if ($addTypeOpen -and $marshalOpen) {
    Write-Host "    [VERDICT] BOTH primitives reachable -> the engine is AMSI-bypassable." -ForegroundColor Red
    Write-Host "              Whether the AV catches a given bypass string is incidental;" -ForegroundColor Red
    Write-Host "              the door is unlocked. Root cause: $lang. FIX: enforce CLM via WDAC." -ForegroundColor Red
} elseif (-not $addTypeOpen -and -not $marshalOpen) {
    Write-Host "    [VERDICT] Both primitives blocked -> no AMSI-patch bypass can run. CLM is containing the engine." -ForegroundColor Green
} else {
    Write-Host "    [VERDICT] PARTIAL containment ($lang) - one primitive still reachable, not sufficient." -ForegroundColor Yellow
}
Write-Host "[*] Done (nothing modified). SIEM marker: $marker" -ForegroundColor Green
