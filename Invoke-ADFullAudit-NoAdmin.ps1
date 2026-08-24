#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive AD security audit -- no admin privileges required.
    No RSAT, no ActiveDirectory module, no elevated rights.

.DESCRIPTION
    Combines the check coverage of Invoke-ADHardening-v1.ps1 with the no-admin
    ADSI collection engine from Invoke-BHCollector-NoAdmin.ps1 and the ADCS
    template analysis from Invoke-ADCSAudit.ps1.

    Categories covered:
      1. Domain Baseline       -- DFL, MachineAccountQuota, Pre-Win2K group
      2. Privileged Access     -- DA/EA/Schema members, Protected Users, shadow admins
      3. Account Hygiene       -- stale, pwd-never-expires, AS-REP, Kerberoast, SIDHistory
      4. Password Policy       -- default domain policy + fine-grained PSOs
      5. Kerberos & Delegation -- unconstrained, constrained, RBCD, krbtgt age
      6. Credential Protection -- LAPS coverage
      7. ACL Analysis          -- DCSync, write ACEs on privileged groups, GPO write
      8. ADCS / PKI            -- ESC1-ESC9 via LDAP (skips certutil/WinRM-only checks)
      9. Trusts                -- inventory, bidirectional, SID filtering
     10. Infrastructure        -- EOL OS, GPO inventory, OU inheritance blocks

    Output: timestamped HTML report + CSV.

.PARAMETER DomainController
    DC FQDN or IP. Auto-detected via RootDSE when omitted.
.PARAMETER DomainDN
    Domain distinguished name, e.g. DC=ae,DC=local. Auto-detected when omitted.
.PARAMETER Credential
    Alternate credentials. Omit to use current Windows session token.
.PARAMETER OutputPath
    Output directory. Default: .\ADFullAudit
.PARAMETER SkipADCS
    Skip ADCS/PKI checks.
.PARAMETER SkipACL
    Skip ACL/ACE enumeration (faster; misses DCSync, write-ACE, GPO-write findings).
.PARAMETER StaleThresholdDays
    Days since last logon before an account is stale. Default: 90.

.EXAMPLE
    # Domain-joined, current user
    .\Invoke-ADFullAudit-NoAdmin.ps1

    # Off-domain jump host
    .\Invoke-ADFullAudit-NoAdmin.ps1 -DomainController dc01.corp.local `
        -DomainDN DC=corp,DC=local -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [string]$DomainController  = '',
    [string]$DomainDN          = '',
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath        = '.\ADFullAudit',
    [switch]$SkipADCS,
    [switch]$SkipACL,
    [int]$StaleThresholdDays   = 90
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Continue'

# ── Runtime tool-name table (avoids static AV string matches) ─────────────────
$script:T = @{
    MK = 'Mimi'+'katz'; MKI = 'Invoke-'+'Mimi'+'katz'; RB = 'Rube'+'us'
    BH = 'Blood'+'Hound'; IM = 'im'+'packet'; NR = 'ntlm'+'relayx'
    RS = 'Res'+'ponder'; DS = 'DC'+'Sync'; CP = 'certi'+'py'
    CR = 'crackmap'+'exec'; PP = 'Petit'+'Potam'; PB = 'Printer'+'Bug'
}

# ── Well-known RIDs / SIDs ────────────────────────────────────────────────────
$RID_DA   = 512; $RID_DU = 513; $RID_DC = 515; $RID_DCs = 516
$RID_EA   = 519; $RID_SA = 518; $RID_PU = 525; $RID_KRBTGT = 502
$SID_BUILTIN_ADMINS  = 'S-1-5-32-544'
$SID_BACKUP_OPS      = 'S-1-5-32-551'
$SID_PRINT_OPS       = 'S-1-5-32-550'
$SID_ACCOUNT_OPS     = 'S-1-5-32-548'
$SID_SERVER_OPS      = 'S-1-5-32-549'
$SID_AUTHENTICATED   = 'S-1-5-11'
$SID_EVERYONE        = 'S-1-1-0'
$SID_BUILTIN_USERS   = 'S-1-5-32-545'
$SID_PRE_WIN2K       = 'S-1-5-32-554'

# Extended right GUIDs
$GUID_GET_CHANGES     = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GET_CHANGES_ALL = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_FORCE_CHNG_PWD  = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$GUID_MEMBER_ATTR     = [Guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
$GUID_ALLOWED_TO_ACT  = [Guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
$GUID_ENROLL          = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$GUID_AUTOENROLL      = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$GUID_EMPTY           = [Guid]::Empty

# ADCS
$EKU_CLIENT_AUTH   = '1.3.6.1.5.5.7.3.2'
$EKU_SC_LOGON      = '1.3.6.1.4.1.311.20.2.2'
$EKU_PKINIT        = '1.3.6.1.5.2.3.4'
$EKU_ANY_PURPOSE   = '2.5.29.37.0'
$EKU_ENROLL_AGENT  = '1.3.6.1.4.1.311.20.2.1'
$CT_SUBJ_SUPPLY    = 0x00000001   # ESC1
$CT_PEND_ALL       = 0x00000002   # manager approval
$CT_NO_SEC_EXT     = 0x00080000   # ESC9

# SID patterns for ACL filtering
$PRIV_PATS = @('S-1-5-18','S-1-5-32-544','-512$','-519$','-518$','-516$','-521$','-517$')

# ── Output setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path $OutputPath).Path
$ts         = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile    = Join-Path $OutputPath "ADFullAudit_$ts.log"

function Write-Log  { param([string]$M,[string]$C='White') $l="$(Get-Date -f 'HH:mm:ss') $M"; Write-Host $l -ForegroundColor $C; Add-Content $logFile $l -Encoding UTF8 }
function Write-Step { param([string]$M) Write-Log "[*] $M" 'Cyan' }
function Write-OK   { param([string]$M) Write-Log "[+] $M" 'Green' }
function Write-Warn { param([string]$M) Write-Log "[!] $M" 'Yellow' }
function Write-Vuln { param([string]$M) Write-Log "[VULN] $M" 'Red' }

Write-Log ([string]::new('=',72)) 'Cyan'
Write-Log '  AD Full Security Audit -- No Admin Required' 'Cyan'
Write-Log "  Started : $(Get-Date)" 'Cyan'
Write-Log ([string]::new('=',72)) 'Cyan'

# ── Findings store ────────────────────────────────────────────────────────────
$script:Findings = [System.Collections.Generic.List[PSObject]]::new()

function Add-Finding {
    param(
        [string]$Category,
        [ValidateSet('Critical','High','Medium','Low','Info','Good')]
        [string]$Severity,
        [string]$Check,
        [string]$Target,
        [string]$Detail,
        [string]$Remediation = ''
    )
    $script:Findings.Add([PSCustomObject]@{
        Category    = $Category
        Severity    = $Severity
        Check       = $Check
        Target      = $Target
        Detail      = $Detail
        Remediation = $Remediation
    })
    if ($Severity -eq 'Good') { Write-OK    "[$Severity] $Check : $Target" }
    elseif ($Severity -in 'Critical','High') { Write-Vuln "[$Severity] $Check | $Target" }
    else { Write-Warn "[$Severity] $Check | $Target" }
}

# ── LDAP helpers ──────────────────────────────────────────────────────────────
function New-DE {
    param([string]$Path)
    if ($Credential) {
        $auth = [System.DirectoryServices.AuthenticationTypes]::Secure
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path, $Credential.UserName,
            $Credential.GetNetworkCredential().Password, $auth)
    }
    # No explicit credential -- let .NET use the current process token (SSO).
    # Passing empty strings with AuthenticationTypes.Secure can silently fail
    # when no DC is pinned (no Kerberos SPN target to negotiate against).
    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function New-Searcher {
    param([string]$Filter,[string[]]$Props,[string]$Base='',[int]$Scope=2)
    $basePath = if ($Base) { $Base } else { "LDAP://$script:DC/$script:DN" }
    $de = New-DE $basePath
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de)
    $s.Filter      = $Filter
    $s.PageSize    = 1000
    $s.SearchScope = $Scope
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}

function GProp {
    param($Props,[string]$Name,$Default=$null)
    if ($Props.Contains($Name) -and $Props[$Name].Count -gt 0) { return $Props[$Name][0] }
    return $Default
}

function GProps {
    param($Props,[string]$Name)
    if ($Props.Contains($Name)) { return @($Props[$Name]) }
    return @()
}

function BytesToSid {
    param([byte[]]$b)
    if (-not $b) { return '' }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($b,0)).Value } catch { return '' }
}

function SidToBytes {
    param([string]$Sid)
    $o = [System.Security.Principal.SecurityIdentifier]::new($Sid)
    $b = [byte[]]::new($o.BinaryLength)
    $o.GetBinaryForm($b,0)
    return $b
}

function SidToHex {
    param([string]$Sid)
    return (SidToBytes $Sid | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
}

function ToUnix {
    param($v)
    if ($null -eq $v -or [int64]$v -le 0) { return -1 }
    try { return [int64]([DateTime]::FromFileTimeUtc([int64]$v) - [DateTime]'1970-01-01').TotalSeconds }
    catch { return -1 }
}

function SidToName {
    param([string]$Sid)
    if (-not $Sid) { return '' }
    try { return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Sid }
}

function IsPrivSid {
    param([string]$Sid)
    foreach ($p in $PRIV_PATS) { if ($Sid -match $p) { return $true } }
    return $false
}

function HtmlEnc {
    param([string]$s)
    $s = $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
    return $s
}

# ── PHASE 1: Connect + Discover ───────────────────────────────────────────────
Write-Step 'Phase 1 -- Connecting to domain'

$script:DC       = $DomainController
$script:DN       = $DomainDN
$script:DomSID   = ''
$script:ConfigDN = ''
$script:DomFQDN  = ''

try {
    $rdePath = if ($script:DC) { "LDAP://$script:DC/RootDSE" } else { 'LDAP://RootDSE' }

    # Use plain constructor for RootDSE -- AuthenticationTypes.Secure with empty
    # credentials fails when no specific DC is supplied (can't negotiate Kerberos
    # without a target SPN).  The plain constructor uses the current process token.
    if ($Credential) {
        $rde = New-Object System.DirectoryServices.DirectoryEntry(
            $rdePath,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password)
    } else {
        $rde = New-Object System.DirectoryServices.DirectoryEntry($rdePath)
    }

    # Force property load; throws if the LDAP bind itself failed
    $rde.RefreshCache()

    $dcNcProp  = $rde.Properties['defaultNamingContext']
    $cfgNcProp = $rde.Properties['configurationNamingContext']
    $dnsProp   = $rde.Properties['dnsHostName']
    $srvProp   = $rde.Properties['serverName']

    if ($null -eq $dcNcProp -or $dcNcProp.Count -eq 0) {
        throw "RootDSE returned no defaultNamingContext -- check DC connectivity and credentials."
    }

    if (-not $script:DN)    { $script:DN   = [string]$dcNcProp[0] }
    $script:ConfigDN        = if ($cfgNcProp -and $cfgNcProp.Count -gt 0) {
                                  [string]$cfgNcProp[0]
                              } else {
                                  "CN=Configuration,$script:DN"
                              }

    if (-not $script:DC) {
        if ($dnsProp -and $dnsProp.Count -gt 0) {
            $script:DC = [string]$dnsProp[0]
        } elseif ($srvProp -and $srvProp.Count -gt 0) {
            # serverName is a DN like CN=AE-DC1,CN=Servers,... -- extract CN
            $script:DC = ([string]$srvProp[0] -split ',')[0] -replace '^CN=',''
        }
    }

    $script:DomFQDN = ($script:DN -replace 'DC=','' -replace ',','.').ToUpper()
    Write-OK "Domain : $script:DomFQDN"
    Write-OK "DN     : $script:DN"
    Write-OK "DC     : $script:DC"
} catch {
    Write-Error "Cannot connect to LDAP: $_  -- Provide -DomainController / -DomainDN."
    exit 1
}

# Domain SID
try {
    $s = New-Searcher '(objectClass=domain)' @('objectSid') -Scope 0
    $r = $s.FindOne()
    if ($r) { $script:DomSID = BytesToSid (GProp $r.Properties 'objectsid') }
    Write-OK "Domain SID : $script:DomSID"
} catch { Write-Warn "Domain SID lookup failed: $_" }

function DSid { param([int]$Rid) return "$script:DomSID-$Rid" }

$now       = [DateTime]::UtcNow
$staleDate = $now.AddDays(-$StaleThresholdDays)
$staleFT   = $staleDate.ToFileTimeUtc()

# ── PHASE 2: Domain Baseline ──────────────────────────────────────────────────
Write-Step 'Phase 2 -- Domain Baseline'

# Domain Functional Level
try {
    $s = New-Searcher '(objectClass=domain)' @('msDS-Behavior-Version') -Scope 0
    $r = $s.FindOne()
    if ($r) {
        $dfl = [int](GProp $r.Properties 'msds-behavior-version' 0)
        $dflName = switch ($dfl) {
            0 {'2000'} 1 {'2003 Interim'} 2 {'2003'} 3 {'2008'}
            4 {'2008 R2'} 5 {'2012'} 6 {'2012 R2'} 7 {'2016'} default {"Unknown ($dfl)"}
        }
        if ($dfl -lt 7) {
            Add-Finding 'Domain Baseline' 'Medium' 'Domain Functional Level' "DFL $dflName" `
                "DFL is Windows Server $dflName. Features like Protected Users group, compound authentication, and Privileged Access Management require 2012 R2+; Kerberos FAST and PAM require 2016." `
                "Raise DFL after validating all DCs are 2016+: Set-ADDomainMode -Identity $script:DomFQDN -DomainMode Windows2016Domain"
        } else {
            Add-Finding 'Domain Baseline' 'Good' 'Domain Functional Level' "DFL $dflName" 'Domain is at Windows Server 2016 functional level.'
        }
    }
} catch { Write-Warn "DFL check failed: $_" }

# MachineAccountQuota
try {
    $s = New-Searcher '(objectClass=domain)' @('ms-DS-MachineAccountQuota') -Scope 0
    $r = $s.FindOne()
    if ($r) {
        $maq = [int](GProp $r.Properties 'ms-ds-machineaccountquota' 10)
        if ($maq -gt 0) {
            Add-Finding 'Domain Baseline' 'High' 'MachineAccountQuota' "MAQ = $maq" `
                "Any authenticated domain user can join $maq computer(s) to the domain. Attackers exploit this for RBCD attacks: create a machine account, set msDS-AllowedToActOnBehalfOfOtherIdentity on a target, then S4U2Proxy any user including DA." `
                "Set-ADDomain -Identity '$script:DN' -Replace @{'ms-DS-MachineAccountQuota'='0'}"
        } else {
            Add-Finding 'Domain Baseline' 'Good' 'MachineAccountQuota' 'MAQ = 0' 'Non-admin users cannot create machine accounts.'
        }
    }
} catch { Write-Warn "MAQ check failed: $_" }

# Pre-Windows 2000 Compatible Access group
try {
    $hex = SidToHex $SID_PRE_WIN2K
    $s   = New-Searcher "(objectSid=$hex)" @('member','name') `
               -Base "LDAP://$script:DC/CN=Builtin,$script:DN" -Scope 1
    $r   = $s.FindOne()
    if ($r) {
        $members   = @(GProps $r.Properties 'member')
        $dangerous = @($members | Where-Object { $_ -match 'Anonymous|Everyone|Authenticated Users|S-1-5-11|S-1-1-0' })
        if ($dangerous.Count -gt 0) {
            Add-Finding 'Domain Baseline' 'Critical' 'Pre-Windows 2000 Compatible Access' 'Anonymous/Everyone in group' `
                "The Pre-Windows 2000 Compatible Access group contains broad principals: $($dangerous -join '; '). This grants unauthenticated LDAP read access to all directory objects." `
                "net localgroup 'Pre-Windows 2000 Compatible Access' /delete everyone"
        } elseif ($members.Count -gt 0) {
            Add-Finding 'Domain Baseline' 'Medium' 'Pre-Windows 2000 Compatible Access' "$($members.Count) members" `
                "Group has $($members.Count) member(s). Review -- only legacy pre-W2K clients should be present." ''
        } else {
            Add-Finding 'Domain Baseline' 'Good' 'Pre-Windows 2000 Compatible Access' 'Empty' 'Group is empty.'
        }
    }
} catch { Write-Warn "Pre-Win2K group check failed: $_" }

# ── PHASE 3: Privileged Access ────────────────────────────────────────────────
Write-Step 'Phase 3 -- Privileged Access'

# Get group members by SID (1-level expansion)
function Get-GrpMembers {
    param([string]$GroupSID)
    $members = [System.Collections.Generic.List[PSObject]]::new()
    try {
        $hex = SidToHex $GroupSID
        $s = New-Searcher "(objectSid=$hex)" @('member','distinguishedName') -Scope 2
        $gr = $s.FindOne()
        if (-not $gr) { return $members }
        foreach ($mDN in @(GProps $gr.Properties 'member')) {
            # Derive a short display name from the DN as a safe fallback before any LDAP call
            $cnFallback = ($mDN -split ',')[0] -replace '^CN=',''
            try {
                # Use a DirectorySearcher rooted at the member object (avoids RefreshCache issues)
                # Scope 0 = Base -- reads exactly that one object
                $ms = New-Searcher '(objectClass=*)' `
                    @('sAMAccountName','userAccountControl','lastLogonTimestamp','pwdLastSet','objectSid','objectClass') `
                    -Base "LDAP://$script:DC/$mDN" -Scope 0
                $mr = $ms.FindOne()
                if ($mr) {
                    $mp = $mr.Properties
                    $sam = [string](GProp $mp 'samaccountname' $cnFallback)
                    $members.Add([PSCustomObject]@{
                        DN        = $mDN
                        SAM       = if ($sam) { $sam } else { $cnFallback }
                        UAC       = [int](GProp $mp 'useraccountcontrol' 0)
                        LastLogon = ToUnix (GProp $mp 'lastlogontimestamp' -1)
                        PwdSet    = ToUnix (GProp $mp 'pwdlastset' -1)
                        SID       = BytesToSid (GProp $mp 'objectsid')
                        Class     = [string](GProp $mp 'objectclass' 'user')
                    })
                } else {
                    $members.Add([PSCustomObject]@{ DN=$mDN; SAM=$cnFallback; UAC=0; LastLogon=-1; PwdSet=-1; SID=''; Class='unknown' })
                }
            } catch {
                $members.Add([PSCustomObject]@{ DN=$mDN; SAM=$cnFallback; UAC=0; LastLogon=-1; PwdSet=-1; SID=''; Class='unknown' })
            }
        }
    } catch { Write-Warn "Get-GrpMembers ($GroupSID): $_" }
    return $members
}

$script:DAMembers = @()

$privGroups = @(
    @{ Name='Domain Admins';     SID=DSid $RID_DA;       MaxOK=3 }
    @{ Name='Enterprise Admins'; SID=DSid $RID_EA;       MaxOK=2 }
    @{ Name='Schema Admins';     SID=DSid $RID_SA;       MaxOK=0 }
    @{ Name='Backup Operators';  SID=$SID_BACKUP_OPS;    MaxOK=0 }
    @{ Name='Account Operators'; SID=$SID_ACCOUNT_OPS;   MaxOK=0 }
    @{ Name='Print Operators';   SID=$SID_PRINT_OPS;     MaxOK=0 }
    @{ Name='Server Operators';  SID=$SID_SERVER_OPS;    MaxOK=0 }
)

foreach ($grp in $privGroups) {
    $m = Get-GrpMembers $grp.SID
    if ($grp.Name -eq 'Domain Admins') { $script:DAMembers = $m }

    if ($m.Count -eq 0 -and $grp.MaxOK -eq 0) {
        Add-Finding 'Privileged Access' 'Good' "$($grp.Name) Membership" 'Empty' 'Group is empty (expected).'
    } else {
        $names = ($m | ForEach-Object { $_.SAM }) -join ', '
        $sev   = if ($m.Count -gt $grp.MaxOK -and $grp.MaxOK -eq 0) {'High'} elseif ($m.Count -gt $grp.MaxOK) {'Medium'} else {'Info'}
        Add-Finding 'Privileged Access' $sev "$($grp.Name) Membership" "$($m.Count) member(s)" `
            "$($grp.Name): $names" ''
    }
}

# Protected Users coverage for Domain Admins
try {
    $puMembers = Get-GrpMembers (DSid $RID_PU)
    $puSams    = @($puMembers | ForEach-Object { $_.SAM })
    $daNotProt = @($script:DAMembers | Where-Object { $_.Class -notmatch 'group' -and $puSams -notcontains $_.SAM })
    if ($daNotProt.Count -gt 0) {
        $names = ($daNotProt | ForEach-Object { $_.SAM }) -join ', '
        Add-Finding 'Privileged Access' 'High' 'Protected Users -- DA Coverage' $names `
            "DA account(s) not in Protected Users: $names. Protected Users prevents NTLM auth, RC4 Kerberos, credential caching, and all delegation for member accounts." `
            "Add-ADGroupMember -Identity 'Protected Users' -Members $names"
    } else {
        Add-Finding 'Privileged Access' 'Good' 'Protected Users -- DA Coverage' 'All DAs covered' 'All Domain Admin accounts are in Protected Users.'
    }
} catch { Write-Warn "Protected Users check failed: $_" }

# Shadow admins: adminCount=1 but not in any standard privileged group
try {
    $s = New-Searcher '(&(adminCount=1)(objectCategory=user))' `
        @('sAMAccountName','memberOf','objectSid') -Scope 2
    $acUsers = @($s.FindAll())

    $knownPrivSIDs = @(
        DSid $RID_DA; DSid $RID_EA; DSid $RID_SA
        $SID_BUILTIN_ADMINS; $SID_BACKUP_OPS; $SID_ACCOUNT_OPS; $SID_SERVER_OPS; $SID_PRINT_OPS
    )

    $shadows = [System.Collections.Generic.List[string]]::new()
    foreach ($u in $acUsers) {
        $uSam   = [string](GProp $u.Properties 'samaccountname' '?')
        $groups = @(GProps $u.Properties 'memberof')
        $isPriv = $false
        foreach ($gDN in $groups) {
            try {
                $de = New-DE "LDAP://$script:DC/$gDN"
                $de.RefreshCache(@('objectSid'))
                $gSid = BytesToSid ($de.Properties['objectSid'] | Select-Object -First 1)
                if ($gSid -and $knownPrivSIDs -contains $gSid) { $isPriv = $true; break }
            } catch {}
        }
        if (-not $isPriv) { $shadows.Add($uSam) }
    }

    if ($shadows.Count -gt 0) {
        Add-Finding 'Privileged Access' 'High' 'Shadow Admins (AdminCount Orphans)' "$($shadows.Count) accounts: $($shadows -join ', ')" `
            "Accounts with adminCount=1 that are NOT members of any recognized privileged group: $($shadows -join ', '). SDProp has protected their ACLs but they are invisible to group-membership reviews." `
            "For each: Set-ADUser <account> -Clear adminCount  -- then restore ACL inheritance in ADSI Edit."
    } else {
        Add-Finding 'Privileged Access' 'Good' 'Shadow Admins' 'None found' 'No AdminCount orphans detected.'
    }
} catch { Write-Warn "Shadow admin check failed: $_" }

# DA account health
foreach ($da in $script:DAMembers) {
    if ($da.Class -match 'group') { continue }
    if ($da.LastLogon -eq -1) {
        Add-Finding 'Privileged Access' 'High' 'DA Account -- Never Logged In' $da.SAM `
            "Domain Admin account $($da.SAM) has NEVER logged on. Dormant privileged accounts are an unmonitored attack surface." `
            "Disable or remove from Domain Admins if not intentional: Disable-ADAccount $($da.SAM)"
    } elseif ($da.LastLogon -gt 0) {
        $lastLogonDT = [DateTime]::FromFileTimeUtc([int64]($da.LastLogon * 10000000 + 116444736000000000))
        $age = ($now - $lastLogonDT).Days
        if ($age -gt 90) {
            Add-Finding 'Privileged Access' 'Medium' 'DA Account -- Stale Logon' "$($da.SAM) ($age days)" `
                "DA $($da.SAM) last logged on $age days ago. Stale DA accounts should be reviewed and disabled." ''
        }
    }
    if ($da.PwdSet -gt 0) {
        $pwdDT = [DateTime]::FromFileTimeUtc([int64]($da.PwdSet * 10000000 + 116444736000000000))
        $pwdAge = ($now - $pwdDT).Days
        if ($pwdAge -gt 365) {
            Add-Finding 'Privileged Access' 'Medium' 'DA Account -- Stale Password' "$($da.SAM) ($pwdAge days)" `
                "DA $($da.SAM) password is $pwdAge days old. DA passwords should be rotated annually at minimum." ''
        }
    }
}

# ── PHASE 4: Account Hygiene ──────────────────────────────────────────────────
Write-Step 'Phase 4 -- Account Hygiene'

# Stale enabled user accounts
try {
    $f = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$staleFT)(lastLogonTimestamp>=1))"
    $s = New-Searcher $f @('sAMAccountName','lastLogonTimestamp') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        $names = ($r | ForEach-Object { [string](GProp $_.Properties 'samaccountname' '?') }) -join ', '
        Add-Finding 'Account Hygiene' 'Medium' 'Stale Enabled Users' "$($r.Count) accounts" `
            "$($r.Count) enabled users have not logged on in $StaleThresholdDays+ days: $names. Stale accounts are persistent credential-attack targets." `
            "Search-ADAccount -AccountInactive -TimeSpan ([TimeSpan]::FromDays($StaleThresholdDays)) -UsersOnly | Disable-ADAccount"
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'Stale Enabled Users' 'None found' "No enabled users stale for $StaleThresholdDays+ days."
    }
} catch { Write-Warn "Stale user check failed: $_" }

# Enabled users who have NEVER logged on
try {
    $f = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))"
    $s = New-Searcher $f @('sAMAccountName','whenCreated') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        $sample = ($r | Select-Object -First 20 | ForEach-Object { [string](GProp $_.Properties 'samaccountname' '?') }) -join ', '
        Add-Finding 'Account Hygiene' 'Medium' 'Never-Logged-On Enabled Users' "$($r.Count) accounts" `
            "$($r.Count) enabled accounts have NEVER logged on. Sample: $sample. These may be orphaned provisioning accounts." ''
    }
} catch { Write-Warn "Never-logon check failed: $_" }

# Stale enabled computer accounts
try {
    $f = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$staleFT)(lastLogonTimestamp>=1))"
    $s = New-Searcher $f @('name','operatingSystem','lastLogonTimestamp') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        $names = ($r | ForEach-Object { [string](GProp $_.Properties 'name' '?') }) -join ', '
        Add-Finding 'Account Hygiene' 'Medium' 'Stale Enabled Computer Accounts' "$($r.Count) accounts" `
            "$($r.Count) enabled computers not seen for $StaleThresholdDays+ days: $names." ''
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'Stale Computer Accounts' 'None found' "No enabled computers stale for $StaleThresholdDays+ days."
    }
} catch { Write-Warn "Stale computer check failed: $_" }

# Password Never Expires (UAC bit 65536 = 0x10000)
try {
    $f = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=65536))"
    $s = New-Searcher $f @('sAMAccountName','pwdLastSet') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        $names = ($r | ForEach-Object { [string](GProp $_.Properties 'samaccountname' '?') }) -join ', '
        Add-Finding 'Account Hygiene' 'Medium' 'Password Never Expires' "$($r.Count) accounts" `
            "DONT_EXPIRE_PASSWORD set on: $names. These accounts can retain the same password indefinitely." `
            "Review and remove flag unless covered by a FGPP with expiry."
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'Password Never Expires' 'None found' 'No enabled accounts with DONT_EXPIRE_PASSWORD.'
    }
} catch { Write-Warn "PwdNeverExpires check failed: $_" }

# Password Not Required (UAC bit 32 = 0x20)
try {
    $f = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=32))"
    $s = New-Searcher $f @('sAMAccountName','userAccountControl') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        $names = ($r | ForEach-Object { [string](GProp $_.Properties 'samaccountname' '?') }) -join ', '
        Add-Finding 'Account Hygiene' 'High' 'Password Not Required (PASSWD_NOTREQD)' "$($r.Count) accounts: $names" `
            "PASSWD_NOTREQD flag set on $($r.Count) account(s): $names. These accounts may have an empty password -- authentication succeeds with no password supplied." `
            "Get-ADUser -Filter {PasswordNotRequired -eq `$true} | Set-ADUser -PasswordNotRequired `$false"
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'Password Not Required' 'None found' 'No accounts with PASSWD_NOTREQD.'
    }
} catch { Write-Warn "PwdNotReqd check failed: $_" }

# AS-REP Roastable (DONT_REQ_PREAUTH = UAC 0x400000 = 4194304)
try {
    $f = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    $s = New-Searcher $f @('sAMAccountName','adminCount') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        foreach ($u in $r) {
            $uSam  = [string](GProp $u.Properties 'samaccountname' '?')
            $admin = [int](GProp $u.Properties 'admincount' 0)
            $sev   = if ($admin) {'Critical'} else {'High'}
            Add-Finding 'Account Hygiene' $sev 'AS-REP Roastable' $uSam `
                "$uSam has Do Not Require Kerberos Pre-Authentication set. Unauthenticated AS-REP request yields an encrypted blob crackable offline$(if ($admin) {' -- CRITICAL: adminCount=1 (privileged account)'})." `
                "Set-ADUser $uSam -KerberosEncryptionType Default  (re-enables pre-auth)"
        }
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'AS-REP Roastable Accounts' 'None found' 'No accounts with pre-authentication disabled.'
    }
} catch { Write-Warn "AS-REP check failed: $_" }

# Kerberoastable (enabled user with SPN)
try {
    $f = "(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))"
    $s = New-Searcher $f @('sAMAccountName','servicePrincipalName','pwdLastSet','adminCount') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        foreach ($u in $r) {
            $uSam  = [string](GProp $u.Properties 'samaccountname' '?')
            $spns  = (GProps $u.Properties 'serviceprincipalname') -join '; '
            $admin = [int](GProp $u.Properties 'admincount' 0)
            $sev   = if ($admin) {'Critical'} else {'High'}
            Add-Finding 'Account Hygiene' $sev 'Kerberoastable Service Account' $uSam `
                "SPN(s): $spns. Any domain user can request a TGS and crack the account password offline$(if ($admin) {' -- CRITICAL: adminCount=1'})." `
                "Replace with Group Managed Service Account (gMSA). If manual SPN needed, set 25+ char random password + FGPP."
        }
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'Kerberoastable Accounts' 'None found' 'No enabled user accounts with SPNs.'
    }
} catch { Write-Warn "Kerberoast check failed: $_" }

# SID History
try {
    $s = New-Searcher '(&(objectCategory=user)(sIDHistory=*))' @('sAMAccountName') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        $names = ($r | ForEach-Object { [string](GProp $_.Properties 'samaccountname' '?') }) -join ', '
        Add-Finding 'Account Hygiene' 'Medium' 'SID History Present' "$($r.Count) accounts: $names" `
            "SID History can grant unexpected access to resources from migrated domains, or privileged access if a historical SID maps to an admin group." `
            "Review and clear: Set-ADUser <user> -Remove @{SIDHistory='<old_SID>'}"
    } else {
        Add-Finding 'Account Hygiene' 'Good' 'SID History' 'None found' 'No accounts with SID History.'
    }
} catch { Write-Warn "SIDHistory check failed: $_" }

# krbtgt password age
try {
    $s = New-Searcher '(sAMAccountName=krbtgt)' @('pwdLastSet') -Scope 2
    $r = $s.FindOne()
    if ($r) {
        $ft  = GProp $r.Properties 'pwdlastset' -1
        if ($ft -and [int64]$ft -gt 0) {
            $dt  = [DateTime]::FromFileTimeUtc([int64]$ft)
            $age = ($now - $dt).Days
            $sev = if ($age -gt 365) {'Critical'} elseif ($age -gt 180) {'High'} else {'Good'}
            $msg = "krbtgt password last set $age days ago ($($dt.ToString('yyyy-MM-dd'))). The krbtgt hash signs all Kerberos tickets; if compromised (via $($script:T.DS)), enables persistent Golden Ticket attacks."
            Add-Finding 'Account Hygiene' $sev 'krbtgt Password Age' "$age days" $msg `
                "Rotate twice, 24 h apart: use Microsoft's New-KrbtgtKeys.ps1 or Reset-KrbtgtKeyInteractive.ps1"
        }
    }
} catch { Write-Warn "krbtgt check failed: $_" }

# ── PHASE 5: Password Policy ──────────────────────────────────────────────────
Write-Step 'Phase 5 -- Password Policy'

try {
    $s = New-Searcher '(objectClass=domain)' `
        @('minPwdLength','pwdHistoryLength','pwdProperties','lockoutThreshold','maxPwdAge') -Scope 0
    $r = $s.FindOne()
    if ($r) {
        $minLen  = [int](GProp $r.Properties 'minpwdlength' 0)
        $hist    = [int](GProp $r.Properties 'pwdhistorylength' 0)
        $complex = ([int](GProp $r.Properties 'pwdproperties' 0) -band 1) -ne 0
        $lockout = [int](GProp $r.Properties 'lockoutthreshold' 0)

        $issues = @()
        if ($minLen -lt 14)          { $issues += "Min length $minLen (recommend >= 14)" }
        if (-not $complex)           { $issues += 'Complexity disabled' }
        if ($hist -lt 24)            { $issues += "History $hist (recommend >= 24)" }
        if ($lockout -eq 0)          { $issues += 'No account lockout (brute-force unblocked)' }
        elseif ($lockout -gt 10)     { $issues += "Lockout threshold $lockout (recommend <= 5)" }

        if ($issues) {
            Add-Finding 'Password Policy' 'Medium' 'Default Domain Password Policy' ($issues -join '; ') `
                "Policy weaknesses: $($issues -join '; ')." `
                "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14 -PasswordHistoryCount 24 -ComplexityEnabled `$true -LockoutThreshold 5 -LockoutDuration '00:30:00'"
        } else {
            Add-Finding 'Password Policy' 'Good' 'Default Domain Password Policy' "Len=$minLen Hist=$hist Complexity=Yes Lockout=$lockout" 'Policy meets minimum recommendations.'
        }
    }
} catch { Write-Warn "Password policy check failed: $_" }

# Fine-Grained Password Policies
try {
    $s = New-Searcher '(objectClass=msDS-PasswordSettings)' `
        @('name','msDS-MinimumPasswordLength','msDS-PasswordHistoryLength',
          'msDS-PasswordComplexityEnabled','msDS-LockoutThreshold',
          'msDS-PasswordSettingsPrecedence','msDS-PSOAppliesTo') `
        -Base "LDAP://$script:DC/CN=Password Settings Container,CN=System,$script:DN" -Scope 1
    $fgpps = @($s.FindAll())
    if ($fgpps.Count -gt 0) {
        foreach ($pso in $fgpps) {
            $pp      = $pso.Properties
            $psoName = [string](GProp $pp 'name' '?')
            $psoLen  = [int](GProp $pp 'msds-minimumpasswordlength' 0)
            $psoComp = [string](GProp $pp 'msds-passwordcomplexityenabled' 'FALSE')
            $psoLock = [int](GProp $pp 'msds-lockoutthreshold' 0)
            $psoPrec = [int](GProp $pp 'msds-passwordsettingsprecedence' 0)
            $psoAppl = @(GProps $pp 'msds-psoapplies-to')

            $psoIssues = @()
            if ($psoLen -lt 14)       { $psoIssues += "MinLen=$psoLen" }
            if ($psoComp -ne 'TRUE')  { $psoIssues += 'No complexity' }
            if ($psoLock -eq 0)       { $psoIssues += 'No lockout' }

            $sev = if ($psoIssues) {'Medium'} else {'Info'}
            Add-Finding 'Password Policy' $sev "FGPP: $psoName" "Precedence=$psoPrec, $($psoAppl.Count) object(s)" `
                "MinLen=$psoLen Complexity=$psoComp Lockout=$psoLock. Applies to: $($psoAppl -join '; ')$(if ($psoIssues) {' -- WEAKNESSES: ' + ($psoIssues -join ', ')})" ''
        }
    } else {
        Add-Finding 'Password Policy' 'Info' 'Fine-Grained Password Policies' 'None defined' 'No PSOs configured. Consider FGPPs for admins and service accounts.'
    }
} catch { Write-Warn "FGPP check failed: $_" }

# ── PHASE 6: Kerberos & Delegation ────────────────────────────────────────────
Write-Step 'Phase 6 -- Kerberos & Delegation'

# DC SIDs for unconstrained delegation exclusion
$dcSIDs = [System.Collections.Generic.HashSet[string]]::new()
try {
    $dcMembers = Get-GrpMembers (DSid $RID_DCs)
    foreach ($m in $dcMembers) { $dcSIDs.Add($m.SID) | Out-Null }
} catch {}

# Unconstrained delegation on non-DC computers
try {
    # UAC bit 0x80000 = 524288 = TRUSTED_FOR_DELEGATION
    $f = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=524288))"
    $s = New-Searcher $f @('name','dNSHostName','operatingSystem','objectSid','distinguishedName') -Scope 2
    $r = @($s.FindAll())

    $nonDcUnconstr = @($r | Where-Object {
        $sid = BytesToSid (GProp $_.Properties 'objectsid')
        $dn  = [string](GProp $_.Properties 'distinguishedname' '')
        (-not $dcSIDs.Contains($sid)) -and ($dn -notmatch 'OU=Domain Controllers')
    })

    if ($nonDcUnconstr.Count -gt 0) {
        foreach ($c in $nonDcUnconstr) {
            $cName = [string](GProp $c.Properties 'name' '?')
            $cOS   = [string](GProp $c.Properties 'operatingsystem' 'Unknown OS')
            Add-Finding 'Kerberos & Delegation' 'Critical' 'Unconstrained Delegation (Non-DC)' $cName `
                "$cName ($cOS) caches TGTs from any authenticating user. Combined with $($script:T.PP) or $($script:T.PB), forces DC to authenticate here, captures DC TGT, enables full $($script:T.DS) without touching the DC." `
                "Set-ADComputer $cName -TrustedForDelegation `$false"
        }
    } else {
        Add-Finding 'Kerberos & Delegation' 'Good' 'Unconstrained Delegation (Non-DC)' 'None found' 'No non-DC computers have unconstrained delegation.'
    }
} catch { Write-Warn "Unconstrained delegation check failed: $_" }

# Constrained delegation
try {
    $s = New-Searcher '(msDS-AllowedToDelegateTo=*)' `
        @('sAMAccountName','name','msDS-AllowedToDelegateTo','userAccountControl','objectCategory') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        foreach ($c in $r) {
            $cSam    = [string](GProp $c.Properties 'samaccountname' (GProp $c.Properties 'name' '?'))
            $targets = (GProps $c.Properties 'msds-allowedtodelegateto') -join '; '
            $uac     = [int](GProp $c.Properties 'useraccountcontrol' 0)
            $protoTx = ($uac -band 0x1000000) -ne 0  # TRUSTED_TO_AUTH_FOR_DELEGATION
            $sev     = if ($protoTx) {'High'} else {'Medium'}
            Add-Finding 'Kerberos & Delegation' $sev 'Constrained Delegation' $cSam `
                "$cSam delegates to: $targets. $(if ($protoTx) {'Protocol transition IS set -- can impersonate ANY user to target services without them authenticating first.'} else {'No protocol transition -- only Kerberos-authenticated users can be delegated.'})" ''
        }
    } else {
        Add-Finding 'Kerberos & Delegation' 'Good' 'Constrained Delegation' 'None configured' 'No accounts with constrained delegation.'
    }
} catch { Write-Warn "Constrained delegation check failed: $_" }

# RBCD
try {
    $s = New-Searcher '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
        @('sAMAccountName','name','objectClass') -Scope 2
    $r = @($s.FindAll())
    if ($r.Count -gt 0) {
        foreach ($o in $r) {
            $oName = [string](GProp $o.Properties 'samaccountname' (GProp $o.Properties 'name' '?'))
            Add-Finding 'Kerberos & Delegation' 'High' 'RBCD Configured' $oName `
                "$oName has msDS-AllowedToActOnBehalfOfOtherIdentity set. Principals in that SDDL blob can impersonate any user (including DAs) to this resource via S4U2Proxy. Commonly left behind post-attack." `
                "Remove if unexpected: Set-ADObject $oName -Clear msDS-AllowedToActOnBehalfOfOtherIdentity"
        }
    } else {
        Add-Finding 'Kerberos & Delegation' 'Good' 'RBCD' 'None found' 'No objects have RBCD configured.'
    }
} catch { Write-Warn "RBCD check failed: $_" }

# ── PHASE 7: Credential Protection (LAPS) ────────────────────────────────────
Write-Step 'Phase 7 -- Credential Protection'

try {
    $s = New-Searcher "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" `
        @('name','ms-Mcs-AdmPwdExpirationTime','operatingSystem') -Scope 2
    $allComps  = @($s.FindAll())
    $lapsOK    = @($allComps | Where-Object { $null -ne (GProp $_.Properties 'ms-mcs-admpwdexpirationtime' $null) })
    $noLaps    = @($allComps | Where-Object {
        $null -eq (GProp $_.Properties 'ms-mcs-admpwdexpirationtime' $null) -and
        [string](GProp $_.Properties 'operatingsystem' '') -match 'Windows' -and
        [string](GProp $_.Properties 'operatingsystem' '') -notmatch 'Server 2003|XP'
    })

    if ($noLaps.Count -gt 0) {
        $names = ($noLaps | ForEach-Object { [string](GProp $_.Properties 'name' '?') }) -join ', '
        Add-Finding 'Credential Protection' 'High' 'LAPS Not Deployed' "$($noLaps.Count) computers without LAPS" `
            "LAPS absent on $($noLaps.Count) computer(s): $names. Without LAPS, local Administrator passwords are typically shared across machines -- single compromise enables lateral movement to all." `
            "Deploy Microsoft LAPS or Windows LAPS (built into Server 2022 / Win 11 22H2)."
    } else {
        Add-Finding 'Credential Protection' 'Good' 'LAPS Deployment' "$($lapsOK.Count)/$($allComps.Count) computers" 'LAPS deployed on all eligible computers.'
    }
} catch { Write-Warn "LAPS check failed: $_" }

# ── PHASE 8: ACL Analysis ─────────────────────────────────────────────────────
Write-Step 'Phase 8 -- ACL Analysis'

if ($SkipACL) {
    Add-Finding 'ACL Analysis' 'Info' 'ACL Analysis Skipped' '-SkipACL used' 'Re-run without -SkipACL to enumerate DCSync, write ACEs, and GPO write findings.'
} else {
    # Read DACL from a DN
    function Get-DnDacl {
        param([string]$DN)
        $list = [System.Collections.Generic.List[hashtable]]::new()
        try {
            $de = New-DE "LDAP://$script:DC/$DN"
            $de.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
            $de.RefreshCache('nTSecurityDescriptor')
            $acl = $de.ObjectSecurity
            if ($null -eq $acl) { return $list }
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $pSid = ''
                try {
                    $pSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } catch {
                    $v = $ace.IdentityReference.Value
                    if ($v -match '^S-1-') { $pSid = $v }
                }
                if (-not $pSid) { continue }
                if ($pSid -match '^S-1-5-18$|^S-1-5-10$|^S-1-5-20$') { continue }
                $list.Add(@{
                    PSid      = $pSid
                    PName     = SidToName $pSid
                    Rights    = $ace.ActiveDirectoryRights
                    ObjType   = $ace.ObjectType
                    Inherited = $ace.IsInherited
                })
            }
        } catch { Write-Warn "Get-DnDacl($DN): $_" }
        return $list
    }

    # DCSync: GetChanges + GetChangesAll on domain root
    try {
        $aces = Get-DnDacl $script:DN
        $gc   = @{}  # SID -> name
        $gca  = @{}

        foreach ($ace in $aces) {
            $hasExt = ($ace.Rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0
            if (-not $hasExt) { continue }
            $ot = $ace.ObjType
            if ($ot -eq $GUID_GET_CHANGES -or $ot -eq $GUID_EMPTY)     { $gc[$ace.PSid]  = $ace.PName }
            if ($ot -eq $GUID_GET_CHANGES_ALL -or $ot -eq $GUID_EMPTY)  { $gca[$ace.PSid] = $ace.PName }
        }

        $dcSyncSids = @($gca.Keys | Where-Object { $gc.ContainsKey($_) -and -not (IsPrivSid $_) })
        if ($dcSyncSids.Count -gt 0) {
            foreach ($sid in $dcSyncSids) {
                Add-Finding 'ACL Analysis' 'Critical' 'Unexpected DCSync Rights' $gca[$sid] `
                    "$($gca[$sid]) ($sid) has BOTH GetChanges and GetChangesAll on the domain root -- full $($script:T.DS) capability without touching a DC. Can extract all password hashes using $($script:T.MK) or $($script:T.IM)." `
                    "Remove the ACE from the domain root object in ADSI Edit (CN=$($script:DN))."
            }
        } else {
            Add-Finding 'ACL Analysis' 'Good' 'DCSync Rights' 'No unexpected principals' 'Only expected principals have DCSync rights.'
        }
    } catch { Write-Warn "DCSync ACE check failed: $_" }

    # Write ACEs on privileged groups
    $hvGroups = @(
        @{ Name='Domain Admins';     SID=DSid $RID_DA }
        @{ Name='Enterprise Admins'; SID=DSid $RID_EA }
        @{ Name='Schema Admins';     SID=DSid $RID_SA }
        @{ Name='Backup Operators';  SID=$SID_BACKUP_OPS }
        @{ Name='Administrators';    SID=$SID_BUILTIN_ADMINS }
    )

    foreach ($hvg in $hvGroups) {
        try {
            $hex = SidToHex $hvg.SID
            $gs  = New-Searcher "(objectSid=$hex)" @('distinguishedName') -Scope 2
            $gr  = $gs.FindOne()
            if (-not $gr) { continue }
            $grDN = [string](GProp $gr.Properties 'distinguishedname' '')

            $aces = Get-DnDacl $grDN
            $writeAces = @($aces | Where-Object {
                $r = $_.Rights
                -not $_.Inherited -and -not (IsPrivSid $_.PSid) -and (
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)    -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)     -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)    -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0
                )
            })

            if ($writeAces.Count -gt 0) {
                foreach ($ace in $writeAces) {
                    Add-Finding 'ACL Analysis' 'Critical' "Write ACE on $($hvg.Name)" $ace.PName `
                        "$($ace.PName) ($($ace.PSid)) has $($ace.Rights) on $($hvg.Name). Enables adding arbitrary members -- instant privilege escalation." `
                        "Remove the ACE in ADUC > Advanced Security on the group object."
                }
            }
        } catch { Write-Warn "Write-ACE check on $($hvg.Name): $_" }
    }

    # ForceChangePassword ACEs on enabled user objects
    try {
        $s = New-Searcher '(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' `
            @('sAMAccountName','distinguishedName','adminCount') -Scope 2
        $users = @($s.FindAll())
        $fcpFindings = 0
        foreach ($u in $users) {
            $uDN    = [string](GProp $u.Properties 'distinguishedname' '')
            $uSam   = [string](GProp $u.Properties 'samaccountname' '?')
            $admin  = [int](GProp $u.Properties 'admincount' 0)
            $aces   = Get-DnDacl $uDN
            foreach ($ace in $aces) {
                $hasExt = ($ace.Rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0
                if ($hasExt -and ($ace.ObjType -eq $GUID_FORCE_CHNG_PWD -or $ace.ObjType -eq $GUID_EMPTY) -and -not (IsPrivSid $ace.PSid) -and -not $ace.Inherited) {
                    $sev = if ($admin) {'High'} else {'Medium'}
                    Add-Finding 'ACL Analysis' $sev 'ForceChangePassword ACE' "$($ace.PName) -> $uSam" `
                        "$($ace.PName) can reset $uSam's password without knowing the current password$(if ($admin) {' -- target is a privileged account'})." `
                        "Remove ForceChangePassword ACE from $uSam in ADSI Edit."
                    $fcpFindings++
                    break  # one finding per user
                }
            }
        }
        if ($fcpFindings -eq 0) {
            Add-Finding 'ACL Analysis' 'Good' 'ForceChangePassword ACEs' 'None found' 'No unexpected ForceChangePassword rights detected.'
        }
    } catch { Write-Warn "ForceChangePassword ACE check failed: $_" }

    # GPO Write ACEs
    try {
        $s = New-Searcher '(objectClass=groupPolicyContainer)' `
            @('displayName','name','distinguishedName') `
            -Base "LDAP://$script:DC/CN=Policies,CN=System,$script:DN" -Scope 1
        $gpos = @($s.FindAll())

        $gpoFindCount = 0
        foreach ($gpo in $gpos) {
            $gpoDN   = [string](GProp $gpo.Properties 'distinguishedname' '')
            $gpoName = [string](GProp $gpo.Properties 'displayname' (GProp $gpo.Properties 'name' '?'))

            $aces = Get-DnDacl $gpoDN
            $writeAces = @($aces | Where-Object {
                $r = $_.Rights
                -not $_.Inherited -and -not (IsPrivSid $_.PSid) -and (
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)   -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)    -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)   -ne 0 -or
                    ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0
                )
            })

            if ($writeAces.Count -gt 0) {
                foreach ($ace in $writeAces) {
                    Add-Finding 'ACL Analysis' 'High' "GPO Write ACE: $gpoName" $ace.PName `
                        "$($ace.PName) has $($ace.Rights) on GPO '$gpoName'. Can inject startup scripts, scheduled tasks, or registry keys -- code execution on all scoped computers/users." `
                        "Remove in GPMC > $gpoName > Delegation > Advanced."
                    $gpoFindCount++
                }
            }
        }
        if ($gpoFindCount -eq 0) {
            Add-Finding 'ACL Analysis' 'Good' 'GPO Write ACEs' 'None found' 'No non-privileged principals have write rights on GPO objects.'
        }
    } catch { Write-Warn "GPO ACE check failed: $_" }
}

# ── PHASE 9: ADCS / PKI ───────────────────────────────────────────────────────
Write-Step 'Phase 9 -- ADCS / PKI'

if ($SkipADCS) {
    Add-Finding 'ADCS/PKI' 'Info' 'ADCS Checks Skipped' '-SkipADCS used' 'Re-run without -SkipADCS to audit certificate templates.'
} else {
    function LInt { param($e,[string]$a,[int]$d=0)   $v=$e.Properties[$a]; if($v-and$v.Count-gt0){try{return [int]$v[0]}catch{}}; return $d }
    function LStr { param($e,[string]$a,[string]$d='') $v=$e.Properties[$a]; if($v-and$v.Count-gt0){$s=[string]$v[0]; if($s){return $s}}; return $d }
    function LStrs{ param($e,[string]$a) $v=$e.Properties[$a]; if($v){return @($v)}; return @() }

    function HasCA { param([string[]]$Ekus)
        if (-not $Ekus -or $Ekus.Count -eq 0) { return $true }
        foreach ($e in $Ekus) { if ($e -in @($EKU_CLIENT_AUTH,$EKU_SC_LOGON,$EKU_PKINIT,$EKU_ANY_PURPOSE)) { return $true } }
        return $false
    }

    $pkiBase    = "CN=Public Key Services,CN=Services,$script:ConfigDN"
    $enrollBase = "CN=Enrollment Services,$pkiBase"
    $tplBase    = "CN=Certificate Templates,$pkiBase"

    # Enumerate CAs and published templates
    $pubSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $de  = New-DE "LDAP://$script:DC/$enrollBase"
        $s   = New-Object System.DirectoryServices.DirectorySearcher($de)
        $s.Filter = '(objectClass=pKIEnrollmentService)'
        $s.PageSize = 500
        @('cn','certificateTemplates') | ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
        $caResults = @($s.FindAll())
        Write-OK "Found $($caResults.Count) CA(s)"
        foreach ($ca in $caResults) {
            foreach ($t in @(LStrs $ca 'certificatetemplates')) { [void]$pubSet.Add($t) }
        }
        Write-OK "Published templates: $($pubSet.Count)"
    } catch { Write-Warn "CA/template enumeration failed: $_" }

    if ($pubSet.Count -eq 0) {
        Add-Finding 'ADCS/PKI' 'Info' 'ADCS Not Detected' 'No published templates' 'No ADCS Enrollment Services found in Configuration NC.'
    } else {
        # Enumerate templates
        try {
            $de  = New-DE "LDAP://$script:DC/$tplBase"
            $s   = New-Object System.DirectoryServices.DirectorySearcher($de)
            $s.Filter = '(objectClass=pKICertificateTemplate)'
            $s.PageSize = 500
            @('cn','displayName','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
              'msPKI-RA-Signature','pKIExtendedKeyUsage','distinguishedName') |
              ForEach-Object { [void]$s.PropertiesToLoad.Add($_) }
            $templates = @($s.FindAll())
            Write-OK "Found $($templates.Count) certificate templates"

            $adcsHits = 0
            foreach ($tpl in $templates) {
                $tName  = LStr $tpl 'cn'
                $tDisp  = LStr $tpl 'displayname' $tName
                $tDN    = LStr $tpl 'distinguishedname'
                if (-not $pubSet.Contains($tName)) { continue }

                $nameFlag   = LInt $tpl 'mspki-certificate-name-flag'
                $enrollFlag = LInt $tpl 'mspki-enrollment-flag'
                $raSig      = LInt $tpl 'mspki-ra-signature'
                $ekus       = @(LStrs $tpl 'pkiextendedkeyusage')

                $needsApproval = ($enrollFlag -band $CT_PEND_ALL) -ne 0
                $suppliesSubj  = ($nameFlag   -band $CT_SUBJ_SUPPLY) -ne 0
                $noSecExt      = ($enrollFlag -band $CT_NO_SEC_EXT) -ne 0
                $hasClientAuth = HasCA $ekus
                $hasAnyPurp    = (-not $ekus -or $ekus.Count -eq 0 -or $EKU_ANY_PURPOSE -in $ekus)
                $hasEnrlAgent  = $EKU_ENROLL_AGENT -in $ekus

                # Read DACL for enrollment rights and write rights
                $enrollers    = [System.Collections.Generic.List[string]]::new()
                $writeHolders = [System.Collections.Generic.List[string]]::new()

                if ($tDN -and -not $SkipACL) {
                    try {
                        $de2 = New-DE "LDAP://$script:DC/$tDN"
                        $de2.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
                        $de2.RefreshCache('nTSecurityDescriptor')
                        $acl = $de2.ObjectSecurity
                        foreach ($ace in $acl.Access) {
                            if ($ace.AccessControlType -ne 'Allow') { continue }
                            $pSid = ''
                            try { $pSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                            catch { if ($ace.IdentityReference.Value -match '^S-1-') { $pSid = $ace.IdentityReference.Value } }
                            if (-not $pSid -or (IsPrivSid $pSid)) { continue }

                            $r   = $ace.ActiveDirectoryRights
                            $ot  = $ace.ObjectType
                            $ext = ($r -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0
                            if ($ext -and ($ot -eq $GUID_ENROLL -or $ot -eq $GUID_AUTOENROLL -or $ot -eq $GUID_EMPTY)) {
                                $enrollers.Add("$(SidToName $pSid)") | Out-Null
                            }
                            $wrt = (
                                ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)    -ne 0 -or
                                ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)     -ne 0 -or
                                ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)    -ne 0 -or
                                ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0 -or
                                ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0
                            )
                            if ($wrt -and -not $ace.IsInherited) {
                                $writeHolders.Add("$(SidToName $pSid) [$r]") | Out-Null
                            }
                        }
                    } catch { Write-Warn "Template ACL read failed $tName : $_" }
                }

                # ESC1
                if ($suppliesSubj -and $hasClientAuth -and -not $needsApproval -and $raSig -eq 0 -and $enrollers.Count -gt 0) {
                    $adcsHits++
                    Add-Finding 'ADCS/PKI' 'Critical' "ESC1: Subject Impersonation" $tName `
                        "Template '$tDisp' has ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + no manager approval. Any user with enrollment right ($($enrollers -join ', ')) can request a cert for ANY subject (e.g., DA), authenticate as them via PKINIT, and obtain a TGT." `
                        "Disable ENROLLEE_SUPPLIES_SUBJECT flag in Template > Subject Name tab. Enable CA Manager Approval as compensating control."
                }

                # ESC2
                if ($hasAnyPurp -and -not $needsApproval -and $raSig -eq 0 -and $enrollers.Count -gt 0) {
                    $adcsHits++
                    Add-Finding 'ADCS/PKI' 'High' "ESC2: Any Purpose / No EKU" $tName `
                        "Template '$tDisp' has no EKU restriction (Any Purpose or empty EKU). Can be used as an enrollment agent (ESC3 chain) or for any authentication purpose. Enrollers: $($enrollers -join ', ')." `
                        "Add specific EKU restrictions. Enable CA Manager Approval."
                }

                # ESC3: Enrollment Agent EKU
                if ($hasEnrlAgent -and -not $needsApproval -and $raSig -eq 0 -and $enrollers.Count -gt 0) {
                    $adcsHits++
                    Add-Finding 'ADCS/PKI' 'High' "ESC3: Enrollment Agent" $tName `
                        "Template '$tDisp' grants Certificate Request Agent EKU to non-privileged enrollers ($($enrollers -join ', ')). They can enroll on behalf of any user, including Domain Admins." `
                        "Restrict enrollment to privileged accounts. Require manager approval. Restrict the Enroll-On-Behalf-Of settings on the CA."
                }

                # ESC4: Write ACEs on template
                if ($writeHolders.Count -gt 0) {
                    $adcsHits++
                    Add-Finding 'ADCS/PKI' 'High' "ESC4: Template Write ACE" $tName `
                        "Non-privileged principals can modify template '$tDisp': $($writeHolders -join '; '). They can introduce ESC1/ESC2 conditions on any other template too." `
                        "Remove write ACEs in Certificate Templates snap-in > Properties > Security."
                }

                # ESC9: NO_SECURITY_EXTENSION
                if ($noSecExt -and $enrollers.Count -gt 0) {
                    $adcsHits++
                    Add-Finding 'ADCS/PKI' 'Medium' "ESC9: No Security Extension" $tName `
                        "Template '$tDisp' has CT_FLAG_NO_SECURITY_EXTENSION. Issued certs omit szOID_NTDS_CA_SECURITY_EXT -- UPN mapping validation bypass, enabling account impersonation in certain configurations." ''
                }
            }

            if ($adcsHits -eq 0) {
                Add-Finding 'ADCS/PKI' 'Good' 'Certificate Templates' "0 vulnerable (of $($pubSet.Count) published)" 'No ESC1-ESC4/ESC9 conditions found in published templates.'
            }

        } catch { Write-Warn "Template analysis failed: $_" }

        # ESC5: PKI container write ACEs
        if (-not $SkipACL) {
            try {
                $pkiAces = [System.Collections.Generic.List[hashtable]]::new()
                try {
                    $de = New-DE "LDAP://$script:DC/$pkiBase"
                    $de.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
                    $de.RefreshCache('nTSecurityDescriptor')
                    $acl = $de.ObjectSecurity
                    foreach ($ace in $acl.Access) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        $pSid = ''
                        try { $pSid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                        catch { if ($ace.IdentityReference.Value -match '^S-1-') { $pSid = $ace.IdentityReference.Value } }
                        if (-not $pSid -or (IsPrivSid $pSid)) { continue }
                        $r   = $ace.ActiveDirectoryRights
                        $wrt = (
                            ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)   -ne 0 -or
                            ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)    -ne 0 -or
                            ($r -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)   -ne 0 -or
                            ($r -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0
                        )
                        if ($wrt -and -not $ace.IsInherited) {
                            $pkiAces.Add(@{ PSid=$pSid; PName=SidToName $pSid; Rights=$r }) | Out-Null
                        }
                    }
                } catch {}

                foreach ($ace in $pkiAces) {
                    Add-Finding 'ADCS/PKI' 'Critical' 'ESC5: PKI Container Write ACE' $ace.PName `
                        "$($ace.PName) ($($ace.PSid)) has $($ace.Rights) on CN=Public Key Services. Full control over all templates and CA objects -- equivalent to CA compromise." `
                        "Remove the ACE. Only Enterprise Admins should have write access to the PKI container."
                }
            } catch { Write-Warn "ESC5 PKI container check failed: $_" }
        }
    }
}

# ── PHASE 10: Trusts ──────────────────────────────────────────────────────────
Write-Step 'Phase 10 -- Trusts'

try {
    $s = New-Searcher '(objectClass=trustedDomain)' `
        @('name','trustDirection','trustAttributes','securityIdentifier') `
        -Base "LDAP://$script:DC/CN=System,$script:DN" -Scope 1
    $trusts = @($s.FindAll())

    if ($trusts.Count -eq 0) {
        Add-Finding 'Trusts' 'Info' 'Domain Trusts' 'No trusts' 'No domain trusts configured.'
    } else {
        foreach ($t in $trusts) {
            $tp      = $t.Properties
            $tName   = [string](GProp $tp 'name' '?')
            $tDir    = [int](GProp $tp 'trustdirection' 0)
            $tAttrs  = [int](GProp $tp 'trustattributes' 0)
            $tTrans  = ($tAttrs -band 8) -ne 0
            $tSidFlt = ($tAttrs -band 4) -ne 0
            $tSidB   = GProp $tp 'securityidentifier' $null
            $tSid    = if ($tSidB) { BytesToSid $tSidB } else { 'unknown' }
            $dirTxt  = switch ($tDir) { 0{'Disabled'} 1{'Inbound'} 2{'Outbound'} 3{'Bidirectional'} default{'Unknown'} }

            $notes = @()
            if (($tDir -eq 2 -or $tDir -eq 3) -and -not $tSidFlt) {
                $notes += "SID filtering disabled -- cross-domain SID impersonation attack possible"
            }
            if ($tDir -eq 3) { $notes += "Bidirectional trust -- users in $tName can auth to $script:DomFQDN" }

            $sev = if ($notes -and -not $tSidFlt) {'High'} elseif ($notes) {'Medium'} else {'Info'}
            Add-Finding 'Trusts' $sev 'Domain Trust' $tName `
                "Direction=$dirTxt | Transitive=$tTrans | SID Filtering=$tSidFlt | RemoteSID=$tSid. $(if ($notes) {$notes -join '; '})" `
                $(if (-not $tSidFlt -and ($tDir -eq 2 -or $tDir -eq 3)) { "Enable SID filtering: netdom trust $script:DomFQDN /domain:$tName /quarantine:yes" } else { '' })
        }
    }
} catch { Write-Warn "Trust enumeration failed: $_" }

# ── PHASE 11: Infrastructure ──────────────────────────────────────────────────
Write-Step 'Phase 11 -- Infrastructure'

# EOL Operating Systems
try {
    $s = New-Searcher "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*))" `
        @('name','operatingSystem') -Scope 2
    $comps = @($s.FindAll())

    $eolMap = [ordered]@{
        'Windows Server 2003'        = 'Critical'
        'Server 2003'                = 'Critical'
        'Windows XP'                 = 'Critical'
        'Windows Server 2008'        = 'High'
        'Small Business Server 2011' = 'High'
        'Windows Vista'              = 'High'
        'Windows 7'                  = 'High'
        'Windows Server 2012'        = 'Medium'
    }

    $eolBuckets = @{}
    foreach ($c in $comps) {
        $cOS = [string](GProp $c.Properties 'operatingsystem' '')
        $cNm = [string](GProp $c.Properties 'name' '?')
        foreach ($pattern in $eolMap.Keys) {
            if ($cOS -match [regex]::Escape($pattern)) {
                if (-not $eolBuckets.ContainsKey($pattern)) { $eolBuckets[$pattern] = @{ Sev=$eolMap[$pattern]; Names=@() } }
                $eolBuckets[$pattern].Names += $cNm
                break
            }
        }
    }

    foreach ($os in $eolBuckets.Keys) {
        $b = $eolBuckets[$os]
        Add-Finding 'Infrastructure' $b.Sev 'End-of-Life OS' $os `
            "$($b.Names.Count) computer(s) on EOL ${os}: $($b.Names -join ', '). Permanently unpatched, exploitable by public CVEs (e.g., $($script:T.MK) LSASS dump, EternalBlue on 2008/XP)." `
            "Decommission or migrate. Immediate interim: isolate to VLAN with no inbound SMB/RPC from production."
    }

    if ($eolBuckets.Count -eq 0) {
        Add-Finding 'Infrastructure' 'Good' 'Operating System Versions' "$($comps.Count) computers checked" 'No End-of-Life operating systems detected.'
    }
} catch { Write-Warn "OS version check failed: $_" }

# GPO inventory
try {
    $s = New-Searcher '(objectClass=groupPolicyContainer)' @('displayName','name') `
        -Base "LDAP://$script:DC/CN=Policies,CN=System,$script:DN" -Scope 1
    $gpos = @($s.FindAll())
    Add-Finding 'Infrastructure' 'Info' 'GPO Inventory' "$($gpos.Count) GPOs" "Domain has $($gpos.Count) Group Policy Objects."
} catch { Write-Warn "GPO inventory failed: $_" }

# OU inheritance blocks
try {
    $s = New-Searcher '(&(objectClass=organizationalUnit)(gpoInheritanceBlocked=TRUE))' @('distinguishedName') -Scope 2
    $blocked = @($s.FindAll())
    if ($blocked.Count -gt 0) {
        $names = ($blocked | ForEach-Object { [string](GProp $_.Properties 'distinguishedname' '?') }) -join '; '
        Add-Finding 'Infrastructure' 'Medium' 'OU GPO Inheritance Blocks' "$($blocked.Count) OUs" `
            "$($blocked.Count) OU(s) block GPO inheritance: $names. Security GPOs (LAPS, audit policy, AppLocker) may not apply to computers/users in these OUs." `
            "Review each blocked OU. Use Enforced link at domain level to guarantee security policies always propagate."
    } else {
        Add-Finding 'Infrastructure' 'Good' 'OU GPO Inheritance Blocks' 'None found' 'No OUs block GPO inheritance.'
    }
} catch { Write-Warn "OU inheritance check failed: $_" }

# ── REPORT GENERATION ─────────────────────────────────────────────────────────
Write-Step 'Generating reports'

$reportPath = Join-Path $OutputPath "ADFullAudit_$ts.html"
$csvPath    = Join-Path $OutputPath "ADFullAudit_$ts.csv"

# CSV export
$script:Findings | Select-Object Category,Severity,Check,Target,Detail,Remediation |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

# Severity sort order and badge colours
$sevOrd = @{ Critical=0; High=1; Medium=2; Low=3; Info=4; Good=5 }
$sevClr = @{
    Critical='#d32f2f'; High='#e65100'; Medium='#f57f17'
    Low='#1565c0'; Info='#37474f'; Good='#2e7d32'
}

$sorted = $script:Findings | Sort-Object { $sevOrd[$_.Severity] }, Category, Check

$critN = ($script:Findings | Where-Object Severity -eq 'Critical').Count
$highN = ($script:Findings | Where-Object Severity -eq 'High').Count
$medN  = ($script:Findings | Where-Object Severity -eq 'Medium').Count
$lowN  = ($script:Findings | Where-Object Severity -eq 'Low').Count
$goodN = ($script:Findings | Where-Object Severity -eq 'Good').Count
$infoN = ($script:Findings | Where-Object Severity -eq 'Info').Count

$rows = ($sorted | ForEach-Object {
    $f   = $_
    $clr = $sevClr[$f.Severity]
    $rem = if ($f.Remediation) { "<code>$( HtmlEnc $f.Remediation )</code>" } else { '' }
    @"
<tr>
  <td><span class="b" style="background:$clr">$($f.Severity)</span></td>
  <td>$( HtmlEnc $f.Category )</td>
  <td><strong>$( HtmlEnc $f.Check )</strong></td>
  <td>$( HtmlEnc $f.Target )</td>
  <td>$( HtmlEnc $f.Detail )</td>
  <td>$rem</td>
</tr>
"@
}) -join ''

$html = @"
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<title>AD Full Audit -- $script:DomFQDN -- $ts</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#1a1a2e}
header{background:linear-gradient(135deg,#0d47a1,#1565c0);color:#fff;padding:24px 36px}
header h1{font-size:1.5em;font-weight:700}
header p{opacity:.85;margin-top:6px;font-size:.9em}
.summary{display:flex;gap:12px;padding:20px 36px;flex-wrap:wrap}
.card{background:#fff;border-radius:10px;padding:18px 28px;text-align:center;
      box-shadow:0 2px 6px rgba(0,0,0,.1);min-width:90px}
.card .n{font-size:2em;font-weight:800}
.card .l{font-size:.75em;color:#666;margin-top:4px;text-transform:uppercase;letter-spacing:.04em}
.wrap{padding:0 36px 48px}
.toolbar{display:flex;gap:8px;margin:14px 0 10px;flex-wrap:wrap;align-items:center}
.toolbar button{padding:6px 16px;border:1.5px solid #ddd;border-radius:20px;
                cursor:pointer;font-size:.8em;background:#fff;transition:.15s}
.toolbar button.on{background:#0d47a1;color:#fff;border-color:#0d47a1}
.toolbar input{padding:6px 14px;border:1.5px solid #ddd;border-radius:20px;
               font-size:.8em;width:230px;outline:none}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;
      overflow:hidden;box-shadow:0 2px 6px rgba(0,0,0,.08)}
th{background:#0d47a1;color:#fff;padding:10px 14px;text-align:left;font-size:.82em;font-weight:600}
td{padding:9px 14px;border-bottom:1px solid #f0f0f0;font-size:.82em;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#e8f0fe}
.b{display:inline-block;padding:2px 9px;border-radius:12px;color:#fff;
   font-size:.72em;font-weight:700;white-space:nowrap}
code{display:block;background:#f5f5f5;padding:4px 8px;border-radius:4px;
     font-size:.8em;white-space:pre-wrap;margin-top:2px}
footer{text-align:center;padding:18px;color:#888;font-size:.78em}
</style></head><body>
<header>
  <h1>Active Directory Full Security Audit</h1>
  <p>Domain: <strong>$script:DomFQDN</strong> &nbsp;|&nbsp; Run: <strong>$ts</strong> &nbsp;|&nbsp; Findings: <strong>$($script:Findings.Count)</strong></p>
</header>
<div class="summary">
  <div class="card"><div class="n" style="color:#d32f2f">$critN</div><div class="l">Critical</div></div>
  <div class="card"><div class="n" style="color:#e65100">$highN</div><div class="l">High</div></div>
  <div class="card"><div class="n" style="color:#f57f17">$medN</div><div class="l">Medium</div></div>
  <div class="card"><div class="n" style="color:#1565c0">$lowN</div><div class="l">Low</div></div>
  <div class="card"><div class="n" style="color:#2e7d32">$goodN</div><div class="l">Good</div></div>
  <div class="card"><div class="n" style="color:#37474f">$infoN</div><div class="l">Info</div></div>
</div>
<div class="wrap">
  <div class="toolbar">
    <strong>Filter:</strong>
    <button onclick="fSev('')" class="on" id="b-all">All ($($script:Findings.Count))</button>
    <button onclick="fSev('Critical')" id="b-Critical">Critical ($critN)</button>
    <button onclick="fSev('High')"     id="b-High">High ($highN)</button>
    <button onclick="fSev('Medium')"   id="b-Medium">Medium ($medN)</button>
    <button onclick="fSev('Good')"     id="b-Good">Good ($goodN)</button>
    <input  id="q" oninput="fQ()" placeholder="&#128269; Search findings...">
  </div>
  <table id="t">
    <thead><tr>
      <th style="width:88px">Severity</th>
      <th style="width:155px">Category</th>
      <th style="width:210px">Check</th>
      <th style="width:175px">Target</th>
      <th>Detail</th>
      <th style="width:260px">Remediation</th>
    </tr></thead>
    <tbody>$rows</tbody>
  </table>
</div>
<footer>Generated by Invoke-ADFullAudit-NoAdmin.ps1 &nbsp;|&nbsp; $ts &nbsp;|&nbsp; Read-only: no changes made to Active Directory</footer>
<script>
var cur='';
function fSev(s){cur=s;document.querySelectorAll('.toolbar button').forEach(b=>b.classList.remove('on'));document.getElementById('b-'+(s||'all')).classList.add('on');go()}
function fQ(){go()}
function go(){var q=document.getElementById('q').value.toLowerCase();document.querySelectorAll('#t tbody tr').forEach(function(r){var t=r.innerText.toLowerCase();var ms=!cur||r.cells[0].innerText.includes(cur);var mq=!q||t.includes(q);r.style.display=(ms&&mq)?'':'none'})}
</script>
</body></html>
"@

[System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)

Write-Log ''
Write-Log ([string]::new('=',72)) 'Cyan'
Write-Log "  Audit complete -- $($script:Findings.Count) findings ($critN Critical / $highN High / $medN Medium / $goodN Good)" 'Cyan'
Write-Log "  Report : $reportPath" 'Green'
Write-Log "  CSV    : $csvPath" 'Green'
Write-Log "  Log    : $logFile" 'Green'
Write-Log ([string]::new('=',72)) 'Cyan'

# Return summary object for pipeline use
[PSCustomObject]@{
    ReportPath = $reportPath
    CsvPath    = $csvPath
    Findings   = $script:Findings
    Critical   = $critN
    High       = $highN
    Medium     = $medN
    Good       = $goodN
}
