<#
.SYNOPSIS
    ASPAT -- Full Active Directory Security Audit (Standalone)
.DESCRIPTION
    Audits AD against CIS benchmarks, Kerberos attack surface, delegation
    misconfigs, ADCS (ESC1-ESC8), dormant accounts, LAPS, SIDHistory,
    dangerous ACLs, GPP passwords, and generates a scored HTML+CSV report.
.PARAMETER OutputPath
    Directory for report output. Default: .\Reports
.PARAMETER DomainController
    Target DC. Default: auto-detected.
.PARAMETER SkipADCS
    Skip ADCS checks (faster if ADCS not deployed).
.PARAMETER SkipShares
    Skip SYSVOL/share scanning (can be slow on large domains).
.EXAMPLE
    .\Invoke-ADFullAudit.ps1
    .\Invoke-ADFullAudit.ps1 -OutputPath C:\AuditReports
    .\Invoke-ADFullAudit.ps1 -SkipADCS -SkipShares
.NOTES
    Requires: ActiveDirectory module (RSAT), Domain Admin or equivalent read rights.
    Run as Administrator on a DC or domain-joined host.
#>

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$OutputPath   = ".\Reports",
    [string]$DomainController = "",
    [switch]$SkipADCS,
    [switch]$SkipShares,
    [switch]$NoHtml,
    [switch]$NoCsv
)

Set-StrictMode -Version 2
$ErrorActionPreference = "SilentlyContinue"

#region -- Helpers -------------------------------------------------------------

$script:Findings  = [System.Collections.Generic.List[PSObject]]::new()
$script:Score     = 0
$script:MaxScore  = 0
$script:StartTime = Get-Date

function Add-Finding {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet("Critical","High","Medium","Low","Good","Info")]
        [string]$Severity,
        [string]$Detail,
        [string]$Remediation = "",
        [string]$CIS         = "",
        [string]$MITRE       = "",
        [int]$Score    = 0,
        [int]$MaxScore = 0
    )
    $script:Score    += $Score
    $script:MaxScore += $MaxScore
    $script:Findings.Add([PSCustomObject]@{
        Category    = $Category
        Check       = $Check
        Severity    = $Severity
        Detail      = $Detail
        Remediation = $Remediation
        CIS         = $CIS
        MITRE       = $MITRE
        Score       = $Score
        MaxScore    = $MaxScore
        Timestamp   = (Get-Date -Format "HH:mm:ss")
    })
}

function Write-Status {
    param([string]$Msg, [string]$Color = "White")
    Write-Host $Msg -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n$('-' * 60)" -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host "$('-' * 60)" -ForegroundColor DarkGray
}

function Write-Finding {
    param([string]$Severity, [string]$Text)
    $color = switch ($Severity) {
        "Critical" { "Red" }
        "High"     { "DarkYellow" }
        "Medium"   { "Yellow" }
        "Low"      { "Cyan" }
        "Good"     { "Green" }
        default    { "Gray" }
    }
    $prefix = switch ($Severity) {
        "Critical" { "[!!!]" }
        "High"     { "[ ! ]" }
        "Medium"   { "[ ~ ]" }
        "Good"     { "[ [OK] ]" }
        default    { "[ i ]" }
    }
    Write-Host "  $prefix $Text" -ForegroundColor $color
}

#endregion

#region -- HTML Report ---------------------------------------------------------

function Export-HtmlReport {
    param([string]$Path, [string]$DomainName, [hashtable]$CategoryScores)

    $pct     = if ($script:MaxScore -gt 0) { [math]::Round(($script:Score / $script:MaxScore) * 100) } else { 0 }
    $maturity = switch ($pct) {
        { $_ -ge 91 } { "Level 5 -- Best Practice" }
        { $_ -ge 76 } { "Level 4 -- Managed" }
        { $_ -ge 56 } { "Level 3 -- Defined" }
        { $_ -ge 36 } { "Level 2 -- Developing" }
        default        { "Level 1 -- Critical Exposure" }
    }
    $maturityColor = switch ($pct) {
        { $_ -ge 76 } { "#22c55e" }
        { $_ -ge 56 } { "#eab308" }
        default        { "#ef4444" }
    }

    $critCount = ($script:Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    $highCount = ($script:Findings | Where-Object { $_.Severity -eq "High" }).Count

    $rowsHtml = ($script:Findings | ForEach-Object {
        $bg = switch ($_.Severity) {
            "Critical" { "#fee2e2" }
            "High"     { "#ffedd5" }
            "Medium"   { "#fef9c3" }
            "Good"     { "#dcfce7" }
            default    { "#f8fafc" }
        }
        $badge = switch ($_.Severity) {
            "Critical" { '<span style="background:#ef4444;color:white;padding:2px 8px;border-radius:4px;font-size:11px">CRITICAL</span>' }
            "High"     { '<span style="background:#f97316;color:white;padding:2px 8px;border-radius:4px;font-size:11px">HIGH</span>' }
            "Medium"   { '<span style="background:#eab308;color:white;padding:2px 8px;border-radius:4px;font-size:11px">MEDIUM</span>' }
            "Good"     { '<span style="background:#22c55e;color:white;padding:2px 8px;border-radius:4px;font-size:11px">GOOD</span>' }
            default    { '<span style="background:#94a3b8;color:white;padding:2px 8px;border-radius:4px;font-size:11px">INFO</span>' }
        }
        "<tr style='background:$bg'>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0'>$($_.Category)</td>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0'>$($_.Check)</td>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0'>$badge</td>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0;font-size:12px'>$($_.Detail)</td>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#1d4ed8'>$($_.Remediation)</td>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0;font-size:11px;color:#64748b'>$($_.CIS)</td>
            <td style='padding:8px;border-bottom:1px solid #e2e8f0;font-size:11px;color:#64748b'>$($_.MITRE)</td>
        </tr>"
    }) -join "`n"

    $catRowsHtml = ($CategoryScores.GetEnumerator() | Sort-Object Name | ForEach-Object {
        $catPct = if ($_.Value.Max -gt 0) { [math]::Round(($_.Value.Score / $_.Value.Max) * 100) } else { 0 }
        $barColor = if ($catPct -ge 75) { "#22c55e" } elseif ($catPct -ge 50) { "#eab308" } else { "#ef4444" }
        "<tr>
            <td style='padding:8px;font-weight:600'>$($_.Name)</td>
            <td style='padding:8px'>$($_.Value.Score) / $($_.Value.Max)</td>
            <td style='padding:8px;width:200px'>
                <div style='background:#e2e8f0;border-radius:4px;height:16px'>
                    <div style='background:$barColor;width:$($catPct)%;height:16px;border-radius:4px'></div>
                </div>
            </td>
            <td style='padding:8px;font-weight:bold;color:$barColor'>$catPct%</td>
        </tr>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ASPAT AD Full Audit -- $DomainName</title>
<style>
  body { font-family: 'Segoe UI',Arial,sans-serif; margin:0; background:#f1f5f9; color:#1e293b; }
  .header { background:linear-gradient(135deg,#1e3a5f,#2563eb); color:white; padding:32px 40px; }
  .header h1 { margin:0 0 4px 0; font-size:24px; }
  .header p  { margin:0; opacity:.8; font-size:14px; }
  .cards { display:flex; gap:20px; padding:24px 40px; flex-wrap:wrap; }
  .card { background:white; border-radius:12px; padding:20px 24px; flex:1; min-width:160px;
          box-shadow:0 1px 3px rgba(0,0,0,.1); text-align:center; }
  .card .val { font-size:36px; font-weight:700; }
  .card .lbl { font-size:12px; color:#64748b; margin-top:4px; }
  .section { background:white; margin:0 40px 24px; border-radius:12px;
             box-shadow:0 1px 3px rgba(0,0,0,.1); overflow:hidden; }
  .section h2 { margin:0; padding:16px 24px; background:#f8fafc;
                border-bottom:1px solid #e2e8f0; font-size:15px; color:#1e293b; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { background:#f8fafc; padding:10px 8px; text-align:left; border-bottom:2px solid #e2e8f0;
       font-size:12px; color:#64748b; text-transform:uppercase; letter-spacing:.5px; }
  .footer { text-align:center; padding:24px; color:#94a3b8; font-size:12px; }
</style>
</head>
<body>
<div class="header">
  <h1> ASPAT -- Active Directory Security Audit</h1>
  <p>Domain: <strong>$DomainName</strong> &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; Tool: ASPAT v2.0</p>
</div>

<div class="cards">
  <div class="card">
    <div class="val" style="color:$maturityColor">$pct%</div>
    <div class="lbl">Overall Score ($($script:Score)/$($script:MaxScore))</div>
  </div>
  <div class="card">
    <div class="val" style="color:#1e293b">$maturity</div>
    <div class="lbl">Security Maturity</div>
  </div>
  <div class="card">
    <div class="val" style="color:#ef4444">$critCount</div>
    <div class="lbl">Critical Findings</div>
  </div>
  <div class="card">
    <div class="val" style="color:#f97316">$highCount</div>
    <div class="lbl">High Findings</div>
  </div>
  <div class="card">
    <div class="val" style="color:#64748b">$($script:Findings.Count)</div>
    <div class="lbl">Total Checks</div>
  </div>
</div>

<div class="section">
  <h2> Score by Category</h2>
  <table><thead><tr><th>Category</th><th>Score</th><th>Progress</th><th>%</th></tr></thead>
  <tbody>$catRowsHtml</tbody></table>
</div>

<div class="section">
  <h2> All Findings</h2>
  <table>
    <thead><tr><th>Category</th><th>Check</th><th>Severity</th><th>Detail</th><th>Remediation</th><th>CIS</th><th>MITRE</th></tr></thead>
    <tbody>$rowsHtml</tbody>
  </table>
</div>

<div class="footer">
  Generated by ASPAT (Automated Security Posture Assessment Toolkit) &nbsp;|&nbsp;
  Runtime: $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds))s
</div>
</body></html>
"@
    $html | Out-File -FilePath $Path -Encoding UTF8
}

#endregion

#region -- Main ----------------------------------------------------------------

# Banner
Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|       ASPAT -- FULL AD SECURITY AUDIT v2.0           |" -ForegroundColor Cyan
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host "  Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  User    : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Gray

# Load AD module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Host "`n[FATAL] ActiveDirectory module not available. Install RSAT or run on a DC." -ForegroundColor Red
    exit 2
}

# Domain context
$domain      = Get-ADDomain
$domainDN    = $domain.DistinguishedName
$domainFQDN  = $domain.DNSRoot
$forest      = Get-ADForest
$dcs         = Get-ADDomainController -Filter *

Write-Host "  Domain  : $domainFQDN" -ForegroundColor Gray
Write-Host "  Forest  : $($forest.Name)" -ForegroundColor Gray
Write-Host ""

$catScores = @{}
function Set-CatScore { param([string]$Cat,[int]$S,[int]$M)
    if (-not $catScores.ContainsKey($Cat)) { $catScores[$Cat] = @{Score=0;Max=0} }
    $catScores[$Cat].Score += $S; $catScores[$Cat].Max += $M
}

# -- SECTION 1: CIS Password Policy -----------------------------------------
Write-Section "1/15 -- CIS Password & Lockout Policy"
$dpp = Get-ADDefaultDomainPasswordPolicy
$cisPwd = @(
    @{ Name="Min Password Length >=14";   CIS="1.1.1"; Pass=($dpp.MinPasswordLength -ge 14);      Val=$dpp.MinPasswordLength;                        Pts=3; Fix="Set minimum password length to 14 in Default Domain Policy" }
    @{ Name="Complexity Enabled";        CIS="1.1.2"; Pass=($dpp.ComplexityEnabled);              Val=$dpp.ComplexityEnabled;                        Pts=2; Fix="Enable password complexity requirements" }
    @{ Name="Max Password Age <=60d";     CIS="1.1.3"; Pass=($dpp.MaxPasswordAge.Days -le 60 -and $dpp.MaxPasswordAge.Days -gt 0); Val="$($dpp.MaxPasswordAge.Days)d"; Pts=2; Fix="Set MaxPasswordAge to 60 days" }
    @{ Name="Min Password Age >=1d";      CIS="1.1.4"; Pass=($dpp.MinPasswordAge.Days -ge 1);     Val="$($dpp.MinPasswordAge.Days)d";                Pts=1; Fix="Set MinPasswordAge to 1 day" }
    @{ Name="Password History >=24";      CIS="1.1.5"; Pass=($dpp.PasswordHistoryCount -ge 24);   Val=$dpp.PasswordHistoryCount;                     Pts=2; Fix="Set PasswordHistoryCount to 24" }
    @{ Name="No Reversible Encryption";  CIS="L1";    Pass=(-not $dpp.ReversibleEncryptionEnabled); Val=$dpp.ReversibleEncryptionEnabled;            Pts=3; Fix="Disable reversible password encryption immediately" }
    @{ Name="Lockout Threshold <=5";      CIS="1.2.1"; Pass=($dpp.LockoutThreshold -ge 1 -and $dpp.LockoutThreshold -le 5); Val=$dpp.LockoutThreshold; Pts=3; Fix="Set lockout threshold to 3-5 attempts" }
    @{ Name="Lockout Duration >=15min";   CIS="1.2.2"; Pass=($dpp.LockoutDuration.TotalMinutes -ge 15); Val="$($dpp.LockoutDuration.TotalMinutes)min"; Pts=2; Fix="Set lockout duration to 15+ minutes" }
    @{ Name="Observation Window >=15min"; CIS="1.2.3"; Pass=($dpp.LockoutObservationWindow.TotalMinutes -ge 15); Val="$($dpp.LockoutObservationWindow.TotalMinutes)min"; Pts=2; Fix="Set lockout observation window to 15+ minutes" }
)
foreach ($c in $cisPwd) {
    $sev  = if ($c.Pass) { "Good" } else { if ($c.Pts -ge 3) { "High" } else { "Medium" } }
    $pts  = if ($c.Pass) { $c.Pts } else { 0 }
    $detail = "Current: $($c.Val)"
    Add-Finding "CIS Password Policy" $c.Name $sev $detail $c.Fix $c.CIS "" $pts $c.Pts
    Set-CatScore "CIS Policy" $pts $c.Pts
    Write-Finding $sev "$($c.Name) -- $detail"
}

# -- SECTION 2: AS-REP Roasting ---------------------------------------------
Write-Section "2/15 -- AS-REP Roastable Accounts"
$asrep = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } `
    -Properties DoesNotRequirePreAuth, PasswordLastSet, MemberOf, Description

if ($asrep.Count -eq 0) {
    Add-Finding "Kerberos" "AS-REP Roastable Accounts" "Good" "0 accounts found" "" "" "T1558.004" 5 5
    Set-CatScore "Kerberos" 5 5
    Write-Finding "Good" "No AS-REP roastable accounts"
} else {
    foreach ($u in $asrep) {
        $pwdAge = if ($u.PasswordLastSet) { ((Get-Date)-$u.PasswordLastSet).Days } else { 9999 }
        $isPriv = ($u.MemberOf | Where-Object { $_ -match "Domain Admins|Enterprise Admins|Schema Admins|Administrators" }) -ne $null
        $sev    = if ($isPriv) { "Critical" } else { "High" }
        $detail = "$($u.SamAccountName) | PwdAge: ${pwdAge}d | Privileged: $isPriv"
        Add-Finding "Kerberos" "AS-REP Roastable" $sev $detail "Enable Kerberos pre-authentication on this account" "N/A" "T1558.004" 0 5
        Set-CatScore "Kerberos" 0 5
        Write-Finding $sev "AS-REP: $detail"
    }
}

# -- SECTION 3: Kerberoasting -----------------------------------------------
Write-Section "3/15 -- Kerberoastable Service Accounts"
$kerb = Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and Enabled -eq $true } `
    -Properties ServicePrincipalName, PasswordLastSet, MemberOf, msDS-SupportedEncryptionTypes

if ($kerb.Count -eq 0) {
    Add-Finding "Kerberos" "Kerberoastable Accounts" "Good" "0 user accounts with SPNs" "" "" "T1558.003" 5 5
    Set-CatScore "Kerberos" 5 5
    Write-Finding "Good" "No Kerberoastable user accounts"
} else {
    foreach ($u in $kerb) {
        $pwdAge  = if ($u.PasswordLastSet) { ((Get-Date)-$u.PasswordLastSet).Days } else { 9999 }
        $isPriv  = ($u.MemberOf | Where-Object { $_ -match "Domain Admins|Enterprise Admins|Administrators" }) -ne $null
        $encType = $u.'msDS-SupportedEncryptionTypes'
        $rc4Only = ($null -eq $encType -or $encType -eq 0 -or ($encType -band 4) -eq 0)
        $sev     = if ($isPriv) { "Critical" } elseif ($rc4Only -and $pwdAge -gt 365) { "High" } else { "Medium" }
        $detail  = "$($u.SamAccountName) | PwdAge: ${pwdAge}d | RC4-only: $rc4Only | Privileged: $isPriv"
        $pts     = if ($isPriv) { 0 } elseif ($rc4Only) { 1 } else { 3 }
        Add-Finding "Kerberos" "Kerberoastable" $sev $detail "Rotate password, enforce AES encryption (msDS-SupportedEncryptionTypes=24)" "N/A" "T1558.003" $pts 5
        Set-CatScore "Kerberos" $pts 5
        Write-Finding $sev "Kerb: $detail"
    }
}

# -- SECTION 4: Privileged Groups ------------------------------------------
Write-Section "4/15 -- Privileged Group Audit"
$privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Account Operators",
    "Backup Operators","Server Operators","DnsAdmins","GPO Creator Owners","Protected Users")

foreach ($grp in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $grp -Recursive | Where-Object { $_.objectClass -eq "user" }
        if ($grp -in @("Schema Admins","Enterprise Admins") -and $members.Count -gt 0) {
            Add-Finding "Privileged Groups" "$grp not empty" "High" "$($members.Count) member(s): $($members.SamAccountName -join ', ')" "Remove all members when not actively needed (CIS)" "CIS L1" "T1078.002" 0 4
            Set-CatScore "Privileged Groups" 0 4
            Write-Finding "High" "$grp has $($members.Count) members (should be empty)"
        } else {
            foreach ($m in $members) {
                $u = Get-ADUser $m.SamAccountName -Properties PasswordLastSet, LastLogonDate, PasswordNeverExpires, DoesNotRequirePreAuth, ServicePrincipalName
                $pwdAge  = if ($u.PasswordLastSet) { ((Get-Date)-$u.PasswordLastSet).Days } else { 9999 }
                $lastLog = if ($u.LastLogonDate)   { ((Get-Date)-$u.LastLogonDate).Days }   else { 9999 }
                $flags   = @()
                if ($u.PasswordNeverExpires) { $flags += "PwdNeverExp" }
                if ($u.DoesNotRequirePreAuth){ $flags += "AS-REP!" }
                if ($u.ServicePrincipalName) { $flags += "Kerberoastable!" }
                if ($lastLog -gt 90)         { $flags += "Stale:${lastLog}d" }
                if ($pwdAge -gt 365)         { $flags += "OldPwd:${pwdAge}d" }
                if ($flags) {
                    $sev = if ($flags | Where-Object { $_ -match "AS-REP|Kerberoastable" }) { "Critical" } else { "Medium" }
                    Add-Finding "Privileged Groups" "$grp member flags" $sev "$($u.SamAccountName): $($flags -join ' | ')" "Review and remediate account flags" "" "T1078.002" 0 0
                    Write-Finding $sev "$grp \ $($u.SamAccountName): $($flags -join ' | ')"
                }
            }
        }
    } catch {}
}

# -- SECTION 5: Dangerous Account Flags ------------------------------------
Write-Section "5/15 -- Dangerous Account Flags"

# PasswordNotRequired
$pwdNR = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } -Properties PasswordNotRequired
if ($pwdNR.Count -gt 0) {
    Add-Finding "Account Flags" "PasswordNotRequired" "Critical" "$($pwdNR.Count) accounts: $($pwdNR.SamAccountName -join ', ')" "Unset PASSWD_NOTREQD flag on all accounts" "" "T1078" 0 4
    Set-CatScore "Account Flags" 0 4; Write-Finding "Critical" "PasswordNotRequired on $($pwdNR.Count) accounts"
} else {
    Add-Finding "Account Flags" "PasswordNotRequired" "Good" "No accounts found" "" "" "" 4 4
    Set-CatScore "Account Flags" 4 4; Write-Finding "Good" "No PasswordNotRequired accounts"
}

# Reversible encryption on users
$revEnc = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true }
if ($revEnc.Count -gt 0) {
    Add-Finding "Account Flags" "Reversible Encryption" "Critical" "$($revEnc.Count) accounts" "Disable AllowReversiblePasswordEncryption" "CIS L1" "" 0 3
    Set-CatScore "Account Flags" 0 3; Write-Finding "Critical" "Reversible encryption: $($revEnc.SamAccountName -join ', ')"
} else {
    Add-Finding "Account Flags" "Reversible Encryption" "Good" "None found" "" "" "" 3 3
    Set-CatScore "Account Flags" 3 3; Write-Finding "Good" "No reversible encryption accounts"
}

# SIDHistory
$sidHist = Get-ADUser -Filter { SIDHistory -like "*" } -Properties SIDHistory
if ($sidHist.Count -gt 0) {
    Add-Finding "Account Flags" "SIDHistory Present" "High" "$($sidHist.Count) accounts have SIDHistory -- verify not pointing to privileged SIDs" "Clear sIDHistory attribute if not needed for migration" "" "T1134.005" 0 3
    Set-CatScore "Account Flags" 0 3; Write-Finding "High" "SIDHistory on $($sidHist.Count) accounts"
} else {
    Add-Finding "Account Flags" "SIDHistory" "Good" "No SIDHistory found" "" "" "" 3 3
    Set-CatScore "Account Flags" 3 3; Write-Finding "Good" "No SIDHistory"
}

# DES-only
$desOnly = Get-ADUser -Filter { Enabled -eq $true } -Properties msDS-SupportedEncryptionTypes |
    Where-Object { $null -ne $_.'msDS-SupportedEncryptionTypes' -and ($_.'msDS-SupportedEncryptionTypes' -band 3) -ne 0 -and ($_.'msDS-SupportedEncryptionTypes' -band 24) -eq 0 }
if ($desOnly.Count -gt 0) {
    Add-Finding "Account Flags" "DES-Only Encryption" "High" "$($desOnly.Count) accounts using only DES" "Set msDS-SupportedEncryptionTypes to 24 (AES128+AES256)" "" "T1558" 0 2
    Set-CatScore "Account Flags" 0 2; Write-Finding "High" "DES-only on $($desOnly.Count) accounts"
} else {
    Add-Finding "Account Flags" "DES-Only Encryption" "Good" "No DES-only accounts" "" "" "" 2 2
    Set-CatScore "Account Flags" 2 2; Write-Finding "Good" "No DES-only accounts"
}

# -- SECTION 6: Delegation --------------------------------------------------
Write-Section "6/15 -- Delegation Misconfigurations"
$dcNames = $dcs.Name

$unconstrComp = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Where-Object { $_.Name -notin $dcNames }
if ($unconstrComp.Count -gt 0) {
    Add-Finding "Delegation" "Unconstrained Delegation (Computers)" "Critical" "$($unconstrComp.Count) non-DC computers: $($unconstrComp.Name -join ', ')" "Remove unconstrained delegation -- use constrained or RBCD instead" "" "T1558.001" 0 6
    Set-CatScore "Delegation" 0 6; Write-Finding "Critical" "Unconstrained delegation on: $($unconstrComp.Name -join ', ')"
} else {
    Add-Finding "Delegation" "Unconstrained Delegation (Computers)" "Good" "No non-DC computers found" "" "" "" 6 6
    Set-CatScore "Delegation" 6 6; Write-Finding "Good" "No unconstrained delegation on non-DC computers"
}

$unconstrUser = Get-ADUser -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true }
if ($unconstrUser.Count -gt 0) {
    Add-Finding "Delegation" "Unconstrained Delegation (Users)" "Critical" "$($unconstrUser.SamAccountName -join ', ')" "Remove TrustedForDelegation from user accounts" "" "T1558.001" 0 4
    Set-CatScore "Delegation" 0 4; Write-Finding "Critical" "Unconstrained delegation user accounts: $($unconstrUser.SamAccountName -join ', ')"
} else {
    Add-Finding "Delegation" "Unconstrained Delegation (Users)" "Good" "None found" "" "" "" 4 4
    Set-CatScore "Delegation" 4 4; Write-Finding "Good" "No unconstrained delegation user accounts"
}

$rbcd = Get-ADObject -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like "*" } -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
if ($rbcd.Count -gt 0) {
    Add-Finding "Delegation" "RBCD Configured" "Medium" "$($rbcd.Count) objects with RBCD -- verify all are legitimate" "Review each RBCD entry -- attacker may have configured RBCD for privilege escalation" "" "T1134.001" 1 3
    Set-CatScore "Delegation" 1 3; Write-Finding "Medium" "$($rbcd.Count) objects with RBCD configured"
} else {
    Add-Finding "Delegation" "RBCD" "Good" "No RBCD configured" "" "" "" 3 3
    Set-CatScore "Delegation" 3 3; Write-Finding "Good" "No RBCD configured"
}

# -- SECTION 7: MSOL / DCSync -----------------------------------------------
Write-Section "7/15 -- Azure AD Connect & DCSync Rights"
$msolAccts = Get-ADUser -Filter { SamAccountName -like "MSOL_*" -or SamAccountName -like "AAD_*" -or SamAccountName -like "ADSync*" } `
    -Properties PasswordLastSet, PasswordNeverExpires, Enabled

foreach ($msol in $msolAccts) {
    $age = if ($msol.PasswordLastSet) { ((Get-Date)-$msol.PasswordLastSet).Days } else { 9999 }
    $sev = if ($age -gt 180) { "High" } else { "Medium" }
    Add-Finding "Azure AD Connect" "MSOL/Sync Account" $sev "$($msol.SamAccountName) -- PwdAge: ${age}d | PwdNeverExp: $($msol.PasswordNeverExpires)" "Rotate password regularly; restrict who can read this account" "" "T1078.002" 0 0
    Write-Finding $sev "Sync account: $($msol.SamAccountName) PwdAge: ${age}d"
}

# DCSync rights check
$domainACL = Get-Acl "AD:\$domainDN"
$dcsyncGUIDs = @("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2","1131f6ad-9c07-11d1-f79f-00c04fc2dcd2","89e95b76-444d-4c62-991a-0facbeda640c")
$dcsyncRights = $domainACL.Access | Where-Object {
    ($_.ObjectType.ToString() -in $dcsyncGUIDs) -and $_.ActiveDirectoryRights -match "ExtendedRight" -and
    $_.AccessControlType -eq "Allow" -and
    $_.IdentityReference -notmatch "Domain Controllers|Enterprise Domain Controllers|Administrators|Enterprise Admins|Domain Admins|SYSTEM|NT AUTHORITY"
}
if ($dcsyncRights.Count -gt 0) {
    Add-Finding "Azure AD Connect" "DCSync Rights (Non-Standard)" "Critical" "$($dcsyncRights.IdentityReference -join ', ') has Replicating Directory Changes" "Remove ACE immediately -- these accounts can dump all AD password hashes" "" "T1003.006" 0 5
    Set-CatScore "Azure AD Connect" 0 5; Write-Finding "Critical" "DCSync rights on non-standard accounts: $($dcsyncRights.IdentityReference -join ', ')"
} else {
    Add-Finding "Azure AD Connect" "DCSync Rights" "Good" "No unexpected DCSync rights" "" "" "" 5 5
    Set-CatScore "Azure AD Connect" 5 5; Write-Finding "Good" "No unexpected DCSync rights"
}

# -- SECTION 8: ADCS --------------------------------------------------------
Write-Section "8/15 -- AD Certificate Services (ADCS)"
if (-not $SkipADCS) {
    $adcsCA = Get-ADObject -SearchBase "CN=Public Key Services,CN=Services,CN=Configuration,$domainDN" `
        -Filter { objectClass -eq "pKIEnrollmentService" } -Properties *
    if (-not $adcsCA) {
        Add-Finding "ADCS" "ADCS Deployment" "Info" "No CA found in this domain" "" "" "" 0 0
        Write-Finding "Info" "ADCS not detected"
    } else {
        Write-Finding "Info" "ADCS found: $($adcsCA.Name -join ', ')"
        $templates = Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$domainDN" `
            -Filter { objectClass -eq "pKICertificateTemplate" } -Properties *

        $clientAuthEKUs = @("1.3.6.1.5.5.7.3.2","1.3.6.1.4.1.311.20.2.2","2.5.29.37.0","1.3.6.1.5.2.3.4")
        $esc1Count = 0; $esc2Count = 0; $esc3Count = 0; $esc4Count = 0

        foreach ($t in $templates) {
            $flags      = $t.'msPKI-Certificate-Name-Flag'
            $enrollFlag = $t.'msPKI-Enrollment-Flag'
            $eku        = $t.pKIExtendedKeyUsage
            $noApproval = ($enrollFlag -band 2) -eq 0
            $enrolleeSubj = ($flags -band 1) -ne 0
            $hasClientAuth = ($eku | Where-Object { $_ -in $clientAuthEKUs }) -ne $null

            if ($enrolleeSubj -and $hasClientAuth -and $noApproval) {
                $acl = Get-Acl "AD:\$($t.DistinguishedName)"
                $lowPriv = $acl.Access | Where-Object { $_.IdentityReference -match "Domain Users|Authenticated Users|Everyone" -and $_.ActiveDirectoryRights -match "ExtendedRight" }
                if ($lowPriv) {
                    $esc1Count++
                    Add-Finding "ADCS" "ESC1 -- Enrollee Supplies SAN" "Critical" "Template: $($t.Name) -- any domain user can request cert as DA" "Disable 'Supply in the request' for Subject Name; require CA approval" "" "T1649" 0 5
                    Set-CatScore "ADCS" 0 5; Write-Finding "Critical" "ESC1: $($t.Name)"
                }
            }
            if (($eku -contains "2.5.29.37.0" -or $eku.Count -eq 0) -and $noApproval) {
                $esc2Count++
                Add-Finding "ADCS" "ESC2 -- Any Purpose EKU" "High" "Template: $($t.Name)" "Restrict EKU to specific purposes; enable manager approval" "" "T1649" 0 3
                Set-CatScore "ADCS" 0 3; Write-Finding "High" "ESC2: $($t.Name)"
            }
            if ($eku -contains "1.3.6.1.4.1.311.20.2.1" -and $noApproval) {
                $esc3Count++
                Add-Finding "ADCS" "ESC3 -- Certificate Request Agent" "High" "Template: $($t.Name)" "Enable manager approval or restrict enrollment rights" "" "T1649" 0 3
                Set-CatScore "ADCS" 0 3; Write-Finding "High" "ESC3: $($t.Name)"
            }
        }
        if ($esc1Count -eq 0) { Add-Finding "ADCS" "ESC1 Check" "Good" "No ESC1 templates found" "" "" "" 5 5; Set-CatScore "ADCS" 5 5 }

        # ESC6
        foreach ($ca in $adcsCA) {
            $caFlags = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($ca.Name)" -Name "EditFlags").EditFlags
            if (($caFlags -band 0x00040000) -ne 0) {
                Add-Finding "ADCS" "ESC6 -- EDITF_ATTRIBUTESUBJECTALTNAME2" "Critical" "CA: $($ca.Name) allows SAN in any request" "Disable: certutil -config '$($ca.Name)' -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2" "" "T1649" 0 4
                Set-CatScore "ADCS" 0 4; Write-Finding "Critical" "ESC6 on CA: $($ca.Name)"
            } else {
                Add-Finding "ADCS" "ESC6 Check" "Good" "EDITF_ATTRIBUTESUBJECTALTNAME2 not set on $($ca.Name)" "" "" "" 4 4
                Set-CatScore "ADCS" 4 4
            }
            # ESC8
            try {
                $req = [System.Net.WebRequest]::Create("http://$($ca.dNSHostName)/certsrv/")
                $req.Timeout = 3000; $req.GetResponse() | Out-Null
                Add-Finding "ADCS" "ESC8 -- HTTP Web Enrollment" "Critical" "http://$($ca.dNSHostName)/certsrv/ is reachable -- NTLM relay -> cert" "Disable IIS web enrollment or enforce HTTPS+EPA" "" "T1649" 0 3
                Set-CatScore "ADCS" 0 3; Write-Finding "Critical" "ESC8: HTTP web enrollment on $($ca.dNSHostName)"
            } catch {
                Add-Finding "ADCS" "ESC8 Check" "Good" "Web enrollment not reachable on $($ca.dNSHostName)" "" "" "" 3 3
                Set-CatScore "ADCS" 3 3
            }
        }
    }
} else { Write-Finding "Info" "ADCS checks skipped (-SkipADCS)" }

# -- SECTION 9: SMB Signing -------------------------------------------------
Write-Section "9/15 -- SMB Signing"
$smbUnsigned = @()
foreach ($dc in $dcs) {
    try {
        $smb = Get-SmbServerConfiguration -CimSession $dc.HostName
        if (-not $smb.RequireSecuritySignature) {
            $smbUnsigned += $dc.HostName
            Add-Finding "SMB" "DC SMB Signing" "Critical" "$($dc.HostName) -- RequireSecuritySignature=False" "GPO: Microsoft network server: Digitally sign communications (always) = Enabled" "" "T1557.001" 0 3
            Set-CatScore "SMB" 0 3; Write-Finding "Critical" "SMB signing NOT required on DC: $($dc.HostName)"
        } else {
            Add-Finding "SMB" "DC SMB Signing" "Good" "$($dc.HostName) -- signing required" "" "" "" 3 3
            Set-CatScore "SMB" 3 3; Write-Finding "Good" "SMB signing required: $($dc.HostName)"
        }
    } catch { Write-Finding "Info" "SMB check failed for $($dc.HostName)" }
}

# -- SECTION 10: Dormant Accounts ------------------------------------------
Write-Section "10/15 -- Dormant Accounts"
$staleThreshold = (Get-Date).AddDays(-90)
$staleUsers = Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $staleThreshold } `
    -Properties LastLogonDate, MemberOf | Where-Object { $_.LastLogonDate -ne $null }
$stalePriv = $staleUsers | Where-Object { $_.MemberOf | Where-Object { $_ -match "Domain Admins|Enterprise Admins|Administrators" } }

if ($stalePriv.Count -gt 0) {
    Add-Finding "Dormant Accounts" "Stale Privileged Accounts" "Critical" "$($stalePriv.Count) privileged accounts inactive 90+ days: $($stalePriv.SamAccountName -join ', ')" "Disable immediately; investigate why privileged account is stale" "" "T1078.002" 0 5
    Set-CatScore "Dormant Accounts" 0 5; Write-Finding "Critical" "Stale privileged accounts: $($stalePriv.SamAccountName -join ', ')"
} else {
    Add-Finding "Dormant Accounts" "Stale Privileged Accounts" "Good" "No stale privileged accounts" "" "" "" 5 5
    Set-CatScore "Dormant Accounts" 5 5; Write-Finding "Good" "No stale privileged accounts"
}
if ($staleUsers.Count -gt 0) {
    Add-Finding "Dormant Accounts" "Stale User Accounts (90d)" "Medium" "$($staleUsers.Count) enabled accounts not logged in for 90+ days" "Disable accounts inactive > 90 days; implement lifecycle policy" "" "T1078" 1 3
    Set-CatScore "Dormant Accounts" 1 3; Write-Finding "Medium" "$($staleUsers.Count) stale user accounts"
} else {
    Add-Finding "Dormant Accounts" "Stale User Accounts" "Good" "No stale accounts" "" "" "" 3 3
    Set-CatScore "Dormant Accounts" 3 3; Write-Finding "Good" "No stale user accounts"
}

# -- SECTION 11: LAPS ------------------------------------------------------
Write-Section "11/15 -- LAPS Deployment"
$lapsSchema = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { lDAPDisplayName -eq "ms-MCS-AdmPwd" }
$lapsNewSch = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter { lDAPDisplayName -eq "msLAPS-Password" }

if (-not $lapsSchema -and -not $lapsNewSch) {
    Add-Finding "LAPS" "LAPS Deployment" "High" "LAPS not deployed -- all computers share same local admin password" "Deploy Windows LAPS via GPO: Computer Config > Admin Templates > LAPS" "" "T1078.001" 0 5
    Set-CatScore "LAPS" 0 5; Write-Finding "High" "LAPS not deployed"
} else {
    $totalComps = (Get-ADComputer -Filter { Enabled -eq $true }).Count
    $lapsManaged = (Get-ADComputer -Filter * -Properties ms-MCS-AdmPwd | Where-Object { $_.'ms-MCS-AdmPwd' -ne $null }).Count
    $pctManaged = [math]::Round(($lapsManaged / [math]::Max($totalComps,1)) * 100)
    $sev = if ($pctManaged -ge 90) { "Good" } elseif ($pctManaged -ge 60) { "Medium" } else { "High" }
    $pts = if ($pctManaged -ge 90) { 5 } elseif ($pctManaged -ge 60) { 3 } else { 1 }
    Add-Finding "LAPS" "LAPS Coverage" $sev "$lapsManaged / $totalComps computers managed ($pctManaged%)" "Deploy LAPS to all computers; verify GPO is applied" "" "" $pts 5
    Set-CatScore "LAPS" $pts 5
    Write-Finding $sev "LAPS: $lapsManaged / $totalComps computers ($pctManaged%)"
}

# -- SECTION 12: Dangerous ACLs --------------------------------------------
Write-Section "12/15 -- Dangerous ACLs on High-Value Objects"
$highValueObjs = @($domainDN, "CN=AdminSDHolder,CN=System,$domainDN", "CN=Domain Admins,CN=Users,$domainDN", "CN=Enterprise Admins,CN=Users,$domainDN")
$dangerRights  = @("GenericAll","GenericWrite","WriteDACL","WriteOwner","ExtendedRight","CreateChild")
$ignoredPrins  = "Domain Admins|Enterprise Admins|SYSTEM|Administrators|Creator Owner|ENTERPRISE DOMAIN CONTROLLERS"
$aclRisks = 0

foreach ($obj in $highValueObjs) {
    $acl = Get-Acl "AD:\$obj"
    $risks = $acl.Access | Where-Object {
        ($dangerRights | Where-Object { $_.ActiveDirectoryRights -match $_ }) -ne $null -and
        $_.AccessControlType -eq "Allow" -and $_.IdentityReference -notmatch $ignoredPrins
    }
    if ($risks) {
        $aclRisks++
        Add-Finding "Dangerous ACLs" "Risky ACL on $($obj.Split(',')[0])" "Critical" "$($risks.IdentityReference -join ', ') has $($risks.ActiveDirectoryRights | Select-Object -First 1)" "Remove the ACE; run SDProp to propagate AdminSDHolder" "" "T1484.001" 0 6
        Set-CatScore "Dangerous ACLs" 0 6; Write-Finding "Critical" "ACL risk on $($obj.Split(',')[0])"
    }
}
if ($aclRisks -eq 0) {
    Add-Finding "Dangerous ACLs" "High-Value Object ACLs" "Good" "No risky ACLs on sampled objects" "" "" "" 6 6
    Set-CatScore "Dangerous ACLs" 6 6; Write-Finding "Good" "No risky ACLs on high-value objects"
}

# -- SECTION 13: GPP Passwords (MS14-025) ----------------------------------
Write-Section "13/15 -- GPP Passwords in SYSVOL (MS14-025)"
if (-not $SkipShares) {
    $sysvol   = "\\$domainFQDN\SYSVOL\$domainFQDN"
    $gppFiles = @("Groups.xml","Services.xml","ScheduledTasks.xml","DataSources.xml","Printers.xml","Drives.xml")
    $gppFound = 0
    if (Test-Path $sysvol) {
        foreach ($f in $gppFiles) {
            Get-ChildItem -Path $sysvol -Recurse -Filter $f | Where-Object {
                (Get-Content $_.FullName -Raw) -match "cpassword"
            } | ForEach-Object {
                $gppFound++
                Add-Finding "GPP Credentials" "cpassword in SYSVOL" "Critical" "$($_.FullName)" "Delete file immediately; rotate the account password; audit who accessed SYSVOL" "MS14-025" "T1552.006" 0 4
                Set-CatScore "GPP Credentials" 0 4; Write-Finding "Critical" "cpassword found: $($_.FullName)"
            }
        }
    }
    if ($gppFound -eq 0) {
        Add-Finding "GPP Credentials" "GPP Passwords (MS14-025)" "Good" "No cpassword found in SYSVOL" "" "MS14-025" "" 4 4
        Set-CatScore "GPP Credentials" 4 4; Write-Finding "Good" "No GPP cpassword in SYSVOL"
    }
} else { Write-Finding "Info" "Share checks skipped (-SkipShares)" }

# -- SECTION 14: krbtgt Age ------------------------------------------------
Write-Section "14/15 -- krbtgt & Trust Health"
$krbtgt    = Get-ADUser krbtgt -Properties PasswordLastSet
$krbtgtAge = if ($krbtgt.PasswordLastSet) { ((Get-Date)-$krbtgt.PasswordLastSet).Days } else { 9999 }
$sev       = if ($krbtgtAge -gt 180) { "Critical" } elseif ($krbtgtAge -gt 90) { "High" } else { "Good" }
$pts       = if ($krbtgtAge -le 90) { 4 } elseif ($krbtgtAge -le 180) { 2 } else { 0 }
Add-Finding "krbtgt" "krbtgt Password Age" $sev "Password age: $krbtgtAge days" "Double-rotate krbtgt using the Microsoft script (wait 10h between rotations)" "" "T1558.001" $pts 4
Set-CatScore "krbtgt" $pts 4
Write-Finding $sev "krbtgt password age: $krbtgtAge days"

$trusts = Get-ADTrust -Filter * -Properties *
foreach ($t in $trusts) {
    if (-not $t.SIDFilteringQuarantined) {
        Add-Finding "Trusts" "SID Filtering Disabled" "High" "Trust: $($t.Name) -- SIDFilteringQuarantined=False" "Enable SID filtering to prevent SIDHistory abuse across trusts" "" "T1134.005" 0 3
        Set-CatScore "Trusts" 0 3; Write-Finding "High" "SID filtering disabled on trust: $($t.Name)"
    }
}

# -- SECTION 15: Protected Users -------------------------------------------
Write-Section "15/15 -- Protected Users Coverage"
$protectedMembers = Get-ADGroupMember "Protected Users" -Recursive | Select-Object -ExpandProperty SamAccountName
$daMembers        = Get-ADGroupMember "Domain Admins"   -Recursive | Where-Object { $_.objectClass -eq "user" } | Select-Object -ExpandProperty SamAccountName
$daNotProtected   = $daMembers | Where-Object { $_ -notin $protectedMembers }

if ($daNotProtected.Count -eq 0) {
    Add-Finding "Protected Users" "DA Coverage" "Good" "All Domain Admins are in Protected Users" "" "" "" 4 4
    Set-CatScore "Protected Users" 4 4; Write-Finding "Good" "All DAs in Protected Users group"
} else {
    Add-Finding "Protected Users" "DA Coverage" "High" "$($daNotProtected.Count) DAs not in Protected Users: $($daNotProtected -join ', ')" "Add all DA/EA/Schema Admin accounts to Protected Users group" "" "T1550.002" 0 4
    Set-CatScore "Protected Users" 0 4; Write-Finding "High" "DAs not in Protected Users: $($daNotProtected -join ', ')"
}

#endregion

#region -- Output --------------------------------------------------------------

$pct      = if ($script:MaxScore -gt 0) { [math]::Round(($script:Score / $script:MaxScore) * 100) } else { 0 }
$maturity = switch ($pct) {
    { $_ -ge 91 } { "Level 5 -- Best Practice" }
    { $_ -ge 76 } { "Level 4 -- Managed" }
    { $_ -ge 56 } { "Level 3 -- Defined" }
    { $_ -ge 36 } { "Level 2 -- Developing" }
    default        { "Level 1 -- Critical Exposure" }
}
$critical = $script:Findings | Where-Object { $_.Severity -eq "Critical" }
$high     = $script:Findings | Where-Object { $_.Severity -eq "High" }

Write-Host "`n+======================================================+" -ForegroundColor Cyan
Write-Host "|            AUDIT COMPLETE -- FINAL SCORE             |" -ForegroundColor Cyan
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host "|  Domain  : $($domainFQDN.PadRight(42))|" -ForegroundColor White
Write-Host "|  Score   : $("$($script:Score) / $($script:MaxScore) ($pct%)".PadRight(42))|" -ForegroundColor White
Write-Host "|  Maturity: $($maturity.PadRight(42))|" -ForegroundColor $(if ($pct -ge 76) {"Green"} elseif ($pct -ge 56) {"Yellow"} else {"Red"})
Write-Host "|  Critical: $("$($critical.Count) findings".PadRight(42))|" -ForegroundColor $(if ($critical.Count -gt 0) {"Red"} else {"Green"})
Write-Host "|  High    : $("$($high.Count) findings".PadRight(42))|" -ForegroundColor $(if ($high.Count -gt 0) {"DarkYellow"} else {"Green"})
Write-Host "+======================================================+" -ForegroundColor Cyan

if ($critical.Count -gt 0) {
    Write-Host "`n  CRITICAL FINDINGS -- Fix immediately:" -ForegroundColor Red
    $critical | ForEach-Object { Write-Host "  * [$($_.Category)] $($_.Check): $($_.Detail)" -ForegroundColor Red }
}

# Category scores
Write-Host "`n  Category Scores:" -ForegroundColor Gray
$catScores.GetEnumerator() | Sort-Object Name | ForEach-Object {
    $cp = if ($_.Value.Max -gt 0) { [math]::Round(($_.Value.Score/$_.Value.Max)*100) } else { 0 }
    $bar = ("#" * [math]::Round($cp/5)).PadRight(20)
    $c   = if ($cp -ge 75) { "Green" } elseif ($cp -ge 50) { "Yellow" } else { "Red" }
    Write-Host ("  {0,-22} {1} {2,3}% ({3}/{4})" -f $_.Name, $bar, $cp, $_.Value.Score, $_.Value.Max) -ForegroundColor $c
}

# Reports
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$safeDomain = $domainFQDN -replace '[^a-zA-Z0-9]','_'

if (-not $NoCsv) {
    $csvPath = Join-Path $OutputPath "ADFullAudit_${safeDomain}_${timestamp}.csv"
    $script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`n  CSV  : $csvPath" -ForegroundColor Gray
}

if (-not $NoHtml) {
    $htmlPath = Join-Path $OutputPath "ADFullAudit_${safeDomain}_${timestamp}.html"
    Export-HtmlReport -Path $htmlPath -DomainName $domainFQDN -CategoryScores $catScores
    Write-Host "  HTML : $htmlPath" -ForegroundColor Gray
}

Write-Host "  Runtime: $([math]::Round(((Get-Date)-$script:StartTime).TotalSeconds))s`n" -ForegroundColor Gray

# CI/CD exit code
if ($critical.Count -gt 0) { exit 1 } else { exit 0 }

#endregion
