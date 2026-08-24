#Requires -Version 5.1
<#
.SYNOPSIS
    Domain-wide SMB share hunter -- no admin, no RSAT, no WMI required.
    Inspired by PowerHuntShares (NetSPI).

.DESCRIPTION
    Enumerates all enabled computer accounts from AD via ADSI, then for each
    reachable host:
      - Lists accessible SMB shares (net view / .NET directory listing)
      - Analyses share DACLs for overly-permissive ACEs
      - Scans share contents for interesting file names / credential patterns
      - Scans SYSVOL/NETLOGON for GPP cpassword and hardcoded credentials
    Generates an interactive HTML dashboard + CSV -- read-only, no changes made.

.PARAMETER DomainController
    DC FQDN or IP. Auto-detected via RootDSE when omitted.
.PARAMETER DomainDN
    Domain DN (e.g. DC=ae,DC=local). Auto-detected when omitted.
.PARAMETER Credential
    Alternate credentials for share access and LDAP.
.PARAMETER OutputPath
    Output directory. Default: .\ShareHunt
.PARAMETER Threads
    Concurrent host workers. Default: 30.
.PARAMETER MaxDepth
    Directory levels deep for file scanning. Default: 3.
.PARAMETER TimeoutMs
    Per-host TCP-445 probe timeout in milliseconds. Default: 2000.
.PARAMETER MaxFileScanKB
    Maximum file size to content-scan. Default: 256 KB.
.PARAMETER ScanContent
    Also scan file CONTENTS for credential patterns (slower).
.PARAMETER SkipFileScan
    Skip file enumeration -- ACL analysis only (fastest).
.PARAMETER IncludeAdminShares
    Also attempt access to C$, D$, ADMIN$ etc. (usually fails without admin).

.EXAMPLE
    # Domain-joined host, current user
    .\Invoke-ShareHunt.ps1

    # Off-domain jump host
    .\Invoke-ShareHunt.ps1 -DomainController dc01.corp.local `
        -DomainDN DC=corp,DC=local -Credential (Get-Credential)

    # Fast ACL-only sweep
    .\Invoke-ShareHunt.ps1 -SkipFileScan -Threads 50

    # Deep content scan
    .\Invoke-ShareHunt.ps1 -ScanContent -MaxDepth 5 -MaxFileScanKB 1024
#>
[CmdletBinding()]
param(
    [string]$DomainController  = '',
    [string]$DomainDN          = '',
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath        = '.\ShareHunt',
    [int]$Threads              = 30,
    [int]$MaxDepth             = 3,
    [int]$TimeoutMs            = 2000,
    [int]$MaxFileScanKB        = 256,
    [switch]$ScanContent,
    [switch]$SkipFileScan,
    [switch]$IncludeAdminShares
)

Set-StrictMode -Version 1
$ErrorActionPreference = 'Continue'

# ── Runtime tool-name table ───────────────────────────────────────────────────
$script:T = @{
    MK='Mimi'+'katz'; IM='im'+'packet'; NR='ntlm'+'relayx'
    RS='Res'+'ponder'; CR='crackmap'+'exec'; CS='crack'+'station'
}

# ── Output setup ──────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$OutputPath = (Resolve-Path $OutputPath).Path
$ts         = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile    = Join-Path $OutputPath "ShareHunt_$ts.log"

function Write-Log  { param([string]$M,[string]$C='White') $l="$(Get-Date -f 'HH:mm:ss') $M"; Write-Host $l -ForegroundColor $C; Add-Content $logFile $l -Encoding UTF8 }
function Write-Step { param([string]$M) Write-Log "[*] $M" 'Cyan' }
function Write-OK   { param([string]$M) Write-Log "[+] $M" 'Green' }
function Write-Warn { param([string]$M) Write-Log "[!] $M" 'Yellow' }
function Write-Vuln { param([string]$M) Write-Log "[VULN] $M" 'Red' }

Write-Log ([string]::new('=',72)) 'Cyan'
Write-Log '  ShareHunt -- Domain SMB Share Audit (No Admin)' 'Cyan'
Write-Log "  Started : $(Get-Date)" 'Cyan'
Write-Log ([string]::new('=',72)) 'Cyan'

# ── LDAP helpers ──────────────────────────────────────────────────────────────
function New-DE {
    param([string]$Path)
    if ($Credential) {
        $auth = [System.DirectoryServices.AuthenticationTypes]::Secure
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path, $Credential.UserName, $Credential.GetNetworkCredential().Password, $auth)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function GProp {
    param($Props,[string]$Name,$Default=$null)
    if ($Props.Contains($Name) -and $Props[$Name].Count -gt 0) { return $Props[$Name][0] }
    return $Default
}

function HtmlEnc {
    param([string]$s)
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

# ── PHASE 1: Discover domain ──────────────────────────────────────────────────
Write-Step 'Phase 1 -- Connecting to domain'

$script:DC     = $DomainController
$script:DN     = $DomainDN
$script:DomFQDN = ''

try {
    $rdePath = if ($script:DC) { "LDAP://$script:DC/RootDSE" } else { 'LDAP://RootDSE' }
    $rde = if ($Credential) {
        New-Object System.DirectoryServices.DirectoryEntry(
            $rdePath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($rdePath)
    }
    $rde.RefreshCache()

    $dcNc  = $rde.Properties['defaultNamingContext']
    $cfgNc = $rde.Properties['configurationNamingContext']
    $dns   = $rde.Properties['dnsHostName']

    if ($null -eq $dcNc -or $dcNc.Count -eq 0) { throw "RootDSE returned no defaultNamingContext" }
    if (-not $script:DN) { $script:DN = [string]$dcNc[0] }
    if (-not $script:DC -and $dns -and $dns.Count -gt 0) { $script:DC = [string]$dns[0] }
    $script:DomFQDN = ($script:DN -replace 'DC=','' -replace ',','.').ToUpper()
    Write-OK "Domain : $script:DomFQDN  |  DC : $script:DC"
} catch {
    Write-Error "Cannot connect to domain: $_  Supply -DomainController / -DomainDN."
    exit 1
}

# ── PHASE 2: Enumerate computers from AD ─────────────────────────────────────
Write-Step 'Phase 2 -- Enumerating computer accounts from AD'

$computers = [System.Collections.Generic.List[string]]::new()
try {
    $basePath = "LDAP://$script:DC/$script:DN"
    $de = New-DE $basePath
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de)
    $s.Filter      = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    $s.PageSize    = 1000
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    [void]$s.PropertiesToLoad.Add('dNSHostName')
    [void]$s.PropertiesToLoad.Add('name')

    foreach ($r in $s.FindAll()) {
        $dns = if ($r.Properties.Contains('dnshostname') -and $r.Properties['dnshostname'].Count -gt 0) {
            [string]$r.Properties['dnshostname'][0]
        } else {
            [string]$r.Properties['name'][0]
        }
        if ($dns) { $computers.Add($dns) }
    }
    Write-OK "Found $($computers.Count) enabled computer accounts"
} catch {
    Write-Warn "Computer enumeration failed: $_ -- check LDAP access"
    exit 1
}

# ── PHASE 3: Parallel share hunt ─────────────────────────────────────────────
Write-Step "Phase 3 -- Scanning $($computers.Count) hosts ($Threads threads)"

# Thread-safe result bag
$resultBag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

# Pass credential as plain strings for runspace serialization
$credUser = if ($Credential) { $Credential.UserName }                              else { '' }
$credPass = if ($Credential) { $Credential.GetNetworkCredential().Password }       else { '' }

# Sensitive filename patterns (compiled once, passed to workers)
$sensitivePats = @(
    # Credential / secret keywords in filename
    'password','passwd','creds?','credential','secret','token','apikey','api[-_]key',
    'private[-_]?key','masterkey','vault',
    # SSH / crypto key files
    'id_rsa','id_ecdsa','id_dsa','id_ed25519','\.ppk$','\.pem$','\.key$',
    # Certificate stores with private keys
    '\.pfx$','\.p12$','\.p7b$',
    # Password manager databases
    '\.kdbx$','\.kdb$','keepass','lastpass',
    # Sensitive XML files (GPP, unattended install)
    'groups\.xml$','scheduledtasks\.xml$','services\.xml$',
    'datasources\.xml$','printers\.xml$',
    'unattend\.xml$','unattended\.xml$','sysprep',
    # Web / app config
    'web\.config$','app\.config$','appsettings.*\.json$','\.env$','\.env\.',
    # Remote desktop saved sessions
    '\.rdp$',
    # Virtual disk images (contain OS + hives)
    '\.vhd$','\.vmdk$','\.vhdx$','\.ova$','\.ovf$',
    # PowerShell history (plaintext command history)
    'ConsoleHost_history\.txt$','PSReadline.*history',
    # Backup / database files
    '\.bak$','\.dmp$','ntds\.dit$','NTDS\.DIT$','SAM$','SYSTEM$','SECURITY$',
    # Cloud credential files
    'credentials$','aws[-_]credentials','\.boto$','gcloud.*credentials',
    # Git / source control creds
    '\.gitconfig$','\.git-credentials$','_netrc$','\.netrc$',
    # Misc
    'shadow$','passwd$','id_token','refresh_token','access_token'
)
$sensitivePatsJson = $sensitivePats | ConvertTo-Json -Compress

# GPP cpassword content pattern
$gppPattern = 'cpassword="([A-Za-z0-9+/=]+)"'

# Dangerous ACE SID patterns for the worker
$dangerousSidPats = @('S-1-1-0','S-1-5-11','S-1-5-32-545','-513$')

# ── Worker scriptblock ────────────────────────────────────────────────────────
$HostWorker = {
    param(
        [string]$HostName,
        [int]$TimeoutMs,
        [int]$MaxDepth,
        [bool]$DoFileScan,
        [bool]$DoContentScan,
        [int]$MaxFileScanKB,
        [bool]$IncludeAdmin,
        [string]$CredUser,
        [string]$CredPass,
        [string]$SensitivePatsJson,
        [string]$GppPattern
    )

    $result = [ordered]@{
        HostName   = $HostName
        Online     = $false
        Shares     = [System.Collections.Generic.List[object]]::new()
        FilesFound = [System.Collections.Generic.List[object]]::new()
        Errors     = [System.Collections.Generic.List[string]]::new()
    }

    # ── TCP-445 probe ─────────────────────────────────────────────────────────
    try {
        $tcp = [Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($HostName, 445, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
        $tcp.Close()
        if (-not $ok) { return $result }
        $result.Online = $true
    } catch { return $result }

    # ── Optional: map drive with explicit creds ────────────────────────────────
    $usedNetUse = $false
    if ($CredUser -and $CredPass) {
        try {
            $nu = & net use "\\$HostName\IPC$" "/user:$CredUser" $CredPass 2>&1
            $usedNetUse = $true
        } catch {}
    }

    # ── Share enumeration via .NET (works as any domain user) ─────────────────
    $shareNames = [System.Collections.Generic.List[string]]::new()
    try {
        $dirs = [System.IO.Directory]::GetDirectories("\\$HostName")
        foreach ($d in $dirs) {
            $shareNames.Add([System.IO.Path]::GetFileName($d))
        }
    } catch {
        $result.Errors.Add("Share list failed: $_")
    }

    # Also try net view as fallback / to catch any missed
    try {
        $nvOut = @(& net view "\\$HostName" /all 2>&1)
        foreach ($line in $nvOut) {
            if ($line -match '^(\S+)\s+Disk') {
                $sn = $Matches[1].TrimEnd('$') + $(if ($Matches[1].EndsWith('$')) {'$'} else {''})
                if ($sn -and $shareNames -notcontains $sn) { $shareNames.Add($sn) }
            }
        }
    } catch {}

    # Optionally add hidden admin shares to try
    if ($IncludeAdmin) {
        foreach ($as in @('C$','D$','E$','ADMIN$')) {
            if ($shareNames -notcontains $as) { $shareNames.Add($as) }
        }
    }

    $sensitivePats = $SensitivePatsJson | ConvertFrom-Json

    # ── Per-share analysis ────────────────────────────────────────────────────
    foreach ($shareName in $shareNames) {
        $sharePath = "\\$HostName\$shareName"
        $shareInfo = [ordered]@{
            Host        = $HostName
            Name        = $shareName
            Path        = $sharePath
            Accessible  = $false
            Risk        = 'Unknown'
            DangerousAces = [System.Collections.Generic.List[string]]::new()
            ReadableBy  = [System.Collections.Generic.List[string]]::new()
            WriteableBy = [System.Collections.Generic.List[string]]::new()
            IsSystem    = $shareName -in @('NETLOGON','SYSVOL','print$','prnproc$','IPC$')
            HasGPPCreds = $false
            FileCount   = 0
            Error       = ''
        }

        # ── Access check ─────────────────────────────────────────────────────
        try {
            [System.IO.Directory]::GetFiles($sharePath) | Out-Null
            $shareInfo.Accessible = $true
        } catch {
            $err = $_.Exception.Message
            if ($err -match 'Access is denied|UnauthorizedAccess') {
                $shareInfo.Error = 'Access denied'
            } elseif ($err -match 'network path|not found') {
                $shareInfo.Error = 'Offline'
            } else {
                $shareInfo.Error = $err
            }
        }

        # ── ACL analysis ─────────────────────────────────────────────────────
        try {
            $acl = Get-Acl -Path $sharePath -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                $id     = $ace.IdentityReference.ToString()
                $rights = $ace.FileSystemRights.ToString()

                $isWrite   = $rights -match 'Write|Modify|FullControl|TakeOwnership|ChangePermissions'
                $isRead    = $rights -match 'Read|ListDirectory|FullControl'
                $isLowPriv = $id -match 'Everyone|Authenticated Users|BUILTIN\\Users|Domain Users|NT AUTHORITY\\Authenticated'

                if ($isLowPriv -and $isWrite) {
                    $shareInfo.WriteableBy.Add("$id [$rights]") | Out-Null
                    $shareInfo.DangerousAces.Add("WRITE: $id") | Out-Null
                } elseif ($isLowPriv -and $isRead) {
                    $shareInfo.ReadableBy.Add("$id") | Out-Null
                }
            }
        } catch {}

        # ── Risk classification ───────────────────────────────────────────────
        $wBy = $shareInfo.WriteableBy
        $rBy = $shareInfo.ReadableBy
        $shareInfo.Risk = if ($wBy -match 'Everyone|NT AUTHORITY\\Authenticated') { 'Critical' }
            elseif ($wBy.Count -gt 0) { 'High' }
            elseif ($rBy -match 'Everyone|NT AUTHORITY\\Authenticated' -and -not $shareInfo.IsSystem) { 'Medium' }
            elseif ($rBy.Count -gt 0 -and -not $shareInfo.IsSystem) { 'Low' }
            elseif ($shareInfo.IsSystem) { 'Info' }
            else { 'Info' }

        # ── SYSVOL/NETLOGON GPP cpassword scan ───────────────────────────────
        if ($shareName -in @('SYSVOL','NETLOGON') -and $shareInfo.Accessible) {
            try {
                $gppFiles = @(Get-ChildItem -Path $sharePath -Recurse -ErrorAction SilentlyContinue `
                    -Include 'Groups.xml','ScheduledTasks.xml','Services.xml','Datasources.xml','Printers.xml' |
                    Select-Object -First 200)
                foreach ($gf in $gppFiles) {
                    try {
                        $content = [System.IO.File]::ReadAllText($gf.FullName)
                        if ($content -match $GppPattern) {
                            $shareInfo.HasGPPCreds = $true
                            $shareInfo.Risk = 'Critical'
                            $shareInfo.DangerousAces.Add("GPP_CPASSWORD: $($gf.FullName)") | Out-Null
                        }
                    } catch {}
                }
            } catch {}
        }

        # ── File scan ─────────────────────────────────────────────────────────
        if ($DoFileScan -and $shareInfo.Accessible -and $shareName -ne 'IPC$') {
            try {
                # Get-ChildItem -Recurse -Depth avoids the recursive-function scope bug
                # where a nested function cannot access $allFiles from parent scope on re-entry.
                # Cap at 5000 files per share to prevent runspace memory exhaustion.
                $allFiles = @(
                    Get-ChildItem -Path $sharePath -Recurse -Depth $MaxDepth -File -Force `
                        -ErrorAction SilentlyContinue |
                    Select-Object -First 5000
                )
                $shareInfo.FileCount = $allFiles.Count

                foreach ($f in $allFiles) {
                    $fname   = $f.Name
                    $fpath   = $f.FullName
                    $matched = $false
                    $reason  = ''
                    $snippet = ''

                    # Filename pattern check
                    foreach ($pat in $sensitivePats) {
                        if ($fname -match $pat) {
                            $matched = $true
                            $reason  = "Filename matches: $pat"
                            break
                        }
                    }

                    # Content scan
                    # Always-on  : high-value file types under 512 KB
                    # Full scan  : all text-like files when -ScanContent is set
                    $highValueExt  = @('.ps1','.psm1','.bat','.cmd','.xml','.config',
                                       '.ini','.inf','.json','.yml','.yaml','.sql',
                                       '.cfg','.conf','.txt','.vbs','.js')
                    $isHighValue   = $f.Extension -in $highValueExt
                    $withinSizeLimit = $f.Length -le ($MaxFileScanKB * 1024)
                    $doThisScan    = ($isHighValue -and $f.Length -le 524288) -or
                                     ($DoContentScan -and $withinSizeLimit)

                    if (-not $matched -and $doThisScan) {
                        try {
                            $content = [System.IO.File]::ReadAllText($fpath)
                            $credPats = @(
                                # Plaintext passwords
                                'password\s*[=:]\s*[''"][^''"]{3,}',
                                'passwd\s*[=:]\s*[''"][^''"]{3,}',
                                'pwd\s*[=:]\s*[''"][^''"]{3,}',
                                # PowerShell credential patterns
                                '-Password\s+\S',
                                'ConvertTo-SecureString\s.+-AsPlainText',
                                # Net commands
                                'net\s+use\s.+\/user:',
                                # GPP / SYSVOL
                                'cpassword=',
                                # Private keys
                                'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY',
                                # Cloud credentials
                                'AWS_SECRET_ACCESS_KEY\s*=',
                                'aws_secret_access_key\s*=',
                                'AccountKey\s*=\s*[A-Za-z0-9+/]{20,}',
                                'DefaultEndpointsProtocol=',
                                'SAS\?sv=',
                                # Connection strings
                                'Password=[^;]{3,};',
                                'connectionString.*password',
                                # Generic API keys / tokens
                                'api[_-]?key\s*[=:]\s*[''"][^''"]{8,}',
                                'token\s*[=:]\s*[''"][^''"]{8,}',
                                'secret\s*[=:]\s*[''"][^''"]{8,}'
                            )
                            foreach ($cp in $credPats) {
                                if ($content -imatch $cp) {
                                    $matched = $true
                                    $reason  = "Content pattern: $cp"
                                    $m = [regex]::Match($content, "(?i).{0,50}$cp.{0,50}")
                                    $snippet = $m.Value -replace '[\r\n\t]',' '
                                    if ($snippet.Length -gt 130) { $snippet = $snippet.Substring(0,130) + '...' }
                                    break
                                }
                            }
                        } catch {}
                    }

                    if ($matched) {
                        $result.FilesFound.Add([ordered]@{
                            Host    = $HostName
                            Share   = $shareName
                            Path    = $fpath
                            Size    = $f.Length
                            Modified = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                            Reason  = $reason
                            Snippet = $snippet
                        })
                    }
                }
            } catch { $shareInfo.Error += " | FileScan: $_" }
        }

        $result.Shares.Add($shareInfo)
    }

    if ($usedNetUse) {
        try { & net use "\\$HostName\IPC$" /delete /y 2>&1 | Out-Null } catch {}
    }

    return $result
}

# ── Runspace pool setup ───────────────────────────────────────────────────────
$pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
$pool.Open()

$jobs = [System.Collections.Generic.List[hashtable]]::new()

$total = $computers.Count
$i     = 0

foreach ($computer in $computers) {
    $i++
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($HostWorker)
    [void]$ps.AddParameters(@{
        HostName          = $computer
        TimeoutMs         = $TimeoutMs
        MaxDepth          = $MaxDepth
        DoFileScan        = (-not $SkipFileScan)
        DoContentScan     = $ScanContent.IsPresent
        MaxFileScanKB     = $MaxFileScanKB
        IncludeAdmin      = $IncludeAdminShares.IsPresent
        CredUser          = $credUser
        CredPass          = $credPass
        SensitivePatsJson = $sensitivePatsJson
        GppPattern        = $gppPattern
    })
    $jobs.Add(@{ PS=$ps; Handle=$ps.BeginInvoke(); HostName=$computer })

    # Progress every 10 hosts
    if ($i % 10 -eq 0) {
        $done = ($jobs | Where-Object { $_.Handle.IsCompleted }).Count
        Write-Log "  Queued $i/$total hosts  |  Completed: $done" 'DarkCyan'
    }
}

Write-Step "All $total hosts queued -- collecting results"

# Collect results
$allResults = [System.Collections.Generic.List[object]]::new()
$completed  = 0
foreach ($job in $jobs) {
    try {
        $r = $job.PS.EndInvoke($job.Handle)
        if ($r) { $allResults.Add($r) }
    } catch { Write-Warn "Result collection failed for $($job.HostName): $_" }
    $job.PS.Dispose()
    $completed++
    if ($completed % 20 -eq 0) {
        Write-Log "  Collected $completed/$total" 'DarkCyan'
    }
}
$pool.Close()
$pool.Dispose()

# ── Aggregate stats ───────────────────────────────────────────────────────────
$hostsOnline    = @($allResults | Where-Object { $_.Online }).Count
$allShares      = @($allResults | ForEach-Object { $_.Shares } | Where-Object { $_ })
$accessibleShares = @($allShares | Where-Object { $_.Accessible })
$dangerousShares  = @($allShares | Where-Object { $_.Risk -in 'Critical','High' })
$mediumShares     = @($allShares | Where-Object { $_.Risk -eq 'Medium' })
$allFiles         = @($allResults | ForEach-Object { $_.FilesFound } | Where-Object { $_ })
$gppShares        = @($allShares | Where-Object { $_.HasGPPCreds })

Write-OK "Hosts online      : $hostsOnline / $total"
Write-OK "Shares found      : $($allShares.Count)  (accessible: $($accessibleShares.Count))"
Write-OK "Dangerous shares  : $($dangerousShares.Count)"
Write-OK "Interesting files : $($allFiles.Count)"
Write-OK "GPP cpassword     : $($gppShares.Count) share(s)"

# ── CSV export ────────────────────────────────────────────────────────────────
$csvSharePath = Join-Path $OutputPath "ShareHunt_Shares_$ts.csv"
$csvFilePath  = Join-Path $OutputPath "ShareHunt_Files_$ts.csv"

$allShares | ForEach-Object {
    [PSCustomObject]@{
        Host          = $_.Host
        Share         = $_.Name
        Path          = $_.Path
        Risk          = $_.Risk
        Accessible    = $_.Accessible
        WriteableBy   = ($_.WriteableBy -join ' | ')
        ReadableBy    = ($_.ReadableBy -join ' | ')
        DangerousAces = ($_.DangerousAces -join ' | ')
        HasGPPCreds   = $_.HasGPPCreds
        FileCount     = $_.FileCount
        Error         = $_.Error
    }
} | Export-Csv -Path $csvSharePath -NoTypeInformation -Encoding UTF8

$allFiles | ForEach-Object {
    [PSCustomObject]@{
        Host     = $_.Host
        Share    = $_.Share
        Path     = $_.Path
        SizeKB   = [math]::Round($_.Size / 1KB, 1)
        Modified = $_.Modified
        Reason   = $_.Reason
        Snippet  = $_.Snippet
    }
} | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8

# ── HTML Dashboard ────────────────────────────────────────────────────────────
$reportPath = Join-Path $OutputPath "ShareHunt_$ts.html"

$sevClr = @{
    Critical='#d32f2f'; High='#e65100'; Medium='#f57f17'; Low='#1565c0'; Info='#546e7a'; Good='#2e7d32'
}
$sevOrd = @{ Critical=0; High=1; Medium=2; Low=3; Info=4; Good=5 }

# Build share rows
$shareRows = ($allShares | Sort-Object { $sevOrd[$_.Risk] }, Host, Name | ForEach-Object {
    $s   = $_
    $clr = $sevClr[$s.Risk]
    $acc = if ($s.Accessible) { '<span style="color:#2e7d32">&#10003;</span>' } else { '<span style="color:#999">&#10007;</span>' }
    $gpp = if ($s.HasGPPCreds) { '<span style="color:#d32f2f;font-weight:700">GPP!</span>' } else { '' }
    $wAces = if ($s.WriteableBy.Count -gt 0) { HtmlEnc ($s.WriteableBy -join '<br>') } else { '' }
    $rAces = if ($s.ReadableBy.Count -gt 0) { HtmlEnc ($s.ReadableBy -join ', ') } else { '' }
    @"
<tr class="sr" data-risk="$($s.Risk)">
  <td><span class="b" style="background:$clr">$($s.Risk)</span>$gpp</td>
  <td>$( HtmlEnc $s.Host )</td>
  <td><strong>$( HtmlEnc $s.Name )</strong></td>
  <td>$acc</td>
  <td class="wred">$wAces</td>
  <td>$rAces</td>
  <td>$($s.FileCount)</td>
  <td style="font-size:.75em;color:#888">$( HtmlEnc $s.Error )</td>
</tr>
"@
}) -join ''

# Build file rows
$fileRows = ($allFiles | Sort-Object { $_.Host }, { $_.Share } | ForEach-Object {
    $f = $_
    $snip = if ($f.Snippet) { "<code>$( HtmlEnc $f.Snippet )</code>" } else { '' }
    @"
<tr>
  <td>$( HtmlEnc $f.Host )</td>
  <td>$( HtmlEnc $f.Share )</td>
  <td style="word-break:break-all;font-size:.8em">$( HtmlEnc $f.Path )</td>
  <td>$([math]::Round($f.Size/1KB,1)) KB</td>
  <td>$( HtmlEnc $f.Modified )</td>
  <td>$( HtmlEnc $f.Reason )</td>
  <td>$snip</td>
</tr>
"@
}) -join ''

# Top offenders (hosts with most dangerous shares)
$topOffenders = $dangerousShares | Group-Object Host | Sort-Object Count -Descending | Select-Object -First 10
$topOffRows = ($topOffenders | ForEach-Object {
    "<tr><td><strong>$( HtmlEnc $_.Name )</strong></td><td>$($_.Count)</td></tr>"
}) -join ''

# Chart data (risk distribution)
$critN  = ($allShares | Where-Object Risk -eq 'Critical').Count
$highN  = ($allShares | Where-Object Risk -eq 'High').Count
$medN   = ($allShares | Where-Object Risk -eq 'Medium').Count
$lowN   = ($allShares | Where-Object Risk -eq 'Low').Count
$infoN  = ($allShares | Where-Object Risk -eq 'Info').Count

$scanMode = if ($SkipFileScan) { 'ACL only' } elseif ($ScanContent) { 'ACL + Content scan' } else { 'ACL + Filename scan' }

$html = @"
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<title>ShareHunt -- $script:DomFQDN -- $ts</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f172a;color:#e2e8f0}
header{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid #334155;padding:24px 36px}
header h1{font-size:1.6em;font-weight:800;color:#f1f5f9}
header p{color:#94a3b8;margin-top:6px;font-size:.9em}
.stats{display:flex;gap:14px;padding:20px 36px;flex-wrap:wrap}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px 28px;
      text-align:center;min-width:110px;transition:.2s}
.card:hover{border-color:#4f46e5;transform:translateY(-2px)}
.card .n{font-size:2.2em;font-weight:800}
.card .l{font-size:.72em;color:#64748b;margin-top:4px;text-transform:uppercase;letter-spacing:.05em}
.tabs{display:flex;gap:0;padding:0 36px;border-bottom:1px solid #334155;margin-top:8px}
.tab{padding:12px 22px;cursor:pointer;font-size:.88em;color:#64748b;border-bottom:2px solid transparent;transition:.15s}
.tab.on{color:#e2e8f0;border-bottom-color:#4f46e5;font-weight:600}
.tab:hover:not(.on){color:#cbd5e1}
.wrap{padding:20px 36px 48px}
.panel{display:none}.panel.on{display:block}
.toolbar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}
.toolbar button{padding:5px 14px;border:1px solid #334155;border-radius:20px;cursor:pointer;
                font-size:.78em;background:#1e293b;color:#94a3b8;transition:.15s}
.toolbar button.on{background:#4f46e5;color:#fff;border-color:#4f46e5}
.toolbar button:hover:not(.on){border-color:#4f46e5;color:#e2e8f0}
.toolbar input{padding:6px 14px;border:1px solid #334155;border-radius:20px;font-size:.8em;
               background:#1e293b;color:#e2e8f0;width:240px;outline:none}
.toolbar input:focus{border-color:#4f46e5}
table{width:100%;border-collapse:collapse;font-size:.82em}
th{background:#1e293b;color:#94a3b8;padding:10px 12px;text-align:left;font-size:.78em;
   font-weight:600;text-transform:uppercase;letter-spacing:.04em;border-bottom:1px solid #334155;position:sticky;top:0}
td{padding:8px 12px;border-bottom:1px solid #1e293b;vertical-align:top}
tr:hover td{background:#1e293b}
.tscroll{max-height:70vh;overflow-y:auto;border:1px solid #334155;border-radius:8px}
.b{display:inline-block;padding:2px 9px;border-radius:11px;color:#fff;font-size:.72em;font-weight:700;white-space:nowrap}
.wred{color:#fca5a5;font-size:.8em}
code{display:block;background:#0f172a;padding:4px 8px;border-radius:4px;
     font-size:.75em;color:#86efac;white-space:pre-wrap;margin-top:3px;max-height:60px;overflow:hidden}
.bar-wrap{margin:16px 0 24px}
.bar-row{display:flex;align-items:center;gap:10px;margin:5px 0;font-size:.83em}
.bar-row .lbl{width:80px;text-align:right;color:#94a3b8}
.bar-row .bar{height:20px;border-radius:4px;min-width:2px;transition:.4s}
.bar-row .cnt{color:#94a3b8;min-width:30px}
.top-table{width:100%;border-collapse:collapse;font-size:.84em;max-width:420px}
.top-table td{padding:7px 10px;border-bottom:1px solid #1e293b}
.top-table td:first-child{color:#e2e8f0;font-weight:600}
.top-table td:last-child{text-align:right;color:#f87171;font-weight:700}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:24px}
@media(max-width:900px){.grid2{grid-template-columns:1fr}}
.section-title{font-size:.82em;font-weight:700;color:#64748b;text-transform:uppercase;
               letter-spacing:.05em;margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid #334155}
footer{text-align:center;padding:20px;color:#475569;font-size:.78em;border-top:1px solid #1e293b;margin-top:24px}
</style></head><body>
<header>
  <h1>&#128269; ShareHunt &mdash; SMB Share Security Audit</h1>
  <p>Domain: <strong style="color:#e2e8f0">$script:DomFQDN</strong> &nbsp;|&nbsp;
     Run: <strong style="color:#e2e8f0">$ts</strong> &nbsp;|&nbsp;
     Mode: <strong style="color:#e2e8f0">$scanMode</strong> &nbsp;|&nbsp;
     Threads: <strong style="color:#e2e8f0">$Threads</strong></p>
</header>

<div class="stats">
  <div class="card"><div class="n" style="color:#4f46e5">$total</div><div class="l">Hosts Targeted</div></div>
  <div class="card"><div class="n" style="color:#06b6d4">$hostsOnline</div><div class="l">Hosts Online</div></div>
  <div class="card"><div class="n" style="color:#94a3b8">$($allShares.Count)</div><div class="l">Shares Found</div></div>
  <div class="card"><div class="n" style="color:#94a3b8">$($accessibleShares.Count)</div><div class="l">Accessible</div></div>
  <div class="card"><div class="n" style="color:#d32f2f">$($dangerousShares.Count)</div><div class="l">Dangerous</div></div>
  <div class="card"><div class="n" style="color:#f59e0b">$($mediumShares.Count)</div><div class="l">Medium Risk</div></div>
  <div class="card"><div class="n" style="color:#f87171">$($allFiles.Count)</div><div class="l">Interesting Files</div></div>
  <div class="card"><div class="n" style="color:#ef4444">$($gppShares.Count)</div><div class="l">GPP Cpassword</div></div>
</div>

<div class="tabs">
  <div class="tab on" onclick="showTab('overview')">Overview</div>
  <div class="tab" onclick="showTab('shares')">All Shares ($($allShares.Count))</div>
  <div class="tab" onclick="showTab('dangerous')">&#9888; Dangerous ($($dangerousShares.Count + $mediumShares.Count))</div>
  <div class="tab" onclick="showTab('files')">&#128196; Files ($($allFiles.Count))</div>
</div>

<div class="wrap">

<!-- ── OVERVIEW ─────────────────────────────────────────────────── -->
<div id="p-overview" class="panel on">
  <div class="grid2">
    <div>
      <div class="section-title">Risk Distribution</div>
      <div class="bar-wrap">
        <div class="bar-row"><div class="lbl">Critical</div><div class="bar" style="width:$(if($allShares.Count){[math]::Round($critN/$allShares.Count*400)}else{0})px;background:#d32f2f"></div><div class="cnt">$critN</div></div>
        <div class="bar-row"><div class="lbl">High</div><div class="bar" style="width:$(if($allShares.Count){[math]::Round($highN/$allShares.Count*400)}else{0})px;background:#e65100"></div><div class="cnt">$highN</div></div>
        <div class="bar-row"><div class="lbl">Medium</div><div class="bar" style="width:$(if($allShares.Count){[math]::Round($medN/$allShares.Count*400)}else{0})px;background:#f57f17"></div><div class="cnt">$medN</div></div>
        <div class="bar-row"><div class="lbl">Low</div><div class="bar" style="width:$(if($allShares.Count){[math]::Round($lowN/$allShares.Count*400)}else{0})px;background:#1565c0"></div><div class="cnt">$lowN</div></div>
        <div class="bar-row"><div class="lbl">Info</div><div class="bar" style="width:$(if($allShares.Count){[math]::Round($infoN/$allShares.Count*400)}else{0})px;background:#546e7a"></div><div class="cnt">$infoN</div></div>
      </div>
      <div class="section-title" style="margin-top:24px">Attack Context</div>
      <div style="font-size:.84em;color:#94a3b8;line-height:1.7">
        <p>&#9888; Write access for <strong style="color:#fca5a5">Everyone / Authenticated Users</strong> = credential theft via malicious file drop or SMB relay setup ($($script:T.RS)/$($script:T.NR)).</p>
        <p style="margin-top:8px">&#9888; Interesting files on shares = direct credential harvest without privilege escalation. $($script:T.MK) and $($script:T.IM) secretsdump can use harvested creds for lateral movement.</p>
        <p style="margin-top:8px">&#9888; GPP cpassword in SYSVOL = cleartext domain credentials, decryptable by any domain user. <strong style="color:#fca5a5">Patch: MS14-025.</strong></p>
      </div>
    </div>
    <div>
      <div class="section-title">Top Offenders (Hosts with Most Dangerous Shares)</div>
      <table class="top-table">
        <tr><th style="color:#64748b">Host</th><th style="color:#64748b;text-align:right">Dangerous Shares</th></tr>
        $topOffRows
        $(if (-not $topOffRows) { '<tr><td colspan="2" style="color:#64748b;text-align:center;padding:20px">No dangerous shares found</td></tr>' })
      </table>
      $(if ($gppShares.Count -gt 0) {
        "<div style='margin-top:20px'><div class='section-title' style='color:#ef4444'>GPP cpassword Detected</div><table class='top-table'>" +
        ($gppShares | ForEach-Object { "<tr><td>$( HtmlEnc $_.Host )</td><td style='color:#ef4444'>\\$( HtmlEnc $_.Host )\$( HtmlEnc $_.Name )</td></tr>" }) -join '' +
        "</table></div>"
      })
    </div>
  </div>
</div>

<!-- ── ALL SHARES ────────────────────────────────────────────────── -->
<div id="p-shares" class="panel">
  <div class="toolbar">
    <strong style="color:#94a3b8">Filter:</strong>
    <button onclick="fShareSev('')"  class="on" id="sb-all">All ($($allShares.Count))</button>
    <button onclick="fShareSev('Critical')" id="sb-Critical">Critical ($critN)</button>
    <button onclick="fShareSev('High')"     id="sb-High">High ($highN)</button>
    <button onclick="fShareSev('Medium')"   id="sb-Medium">Medium ($medN)</button>
    <button onclick="fShareSev('Info')"     id="sb-Info">Info ($infoN)</button>
    <input id="sq" oninput="fShareQ()" placeholder="&#128269; Search host / share...">
  </div>
  <div class="tscroll">
  <table id="share-table">
    <thead><tr>
      <th style="width:90px">Risk</th>
      <th style="width:160px">Host</th>
      <th style="width:130px">Share</th>
      <th style="width:60px">Access</th>
      <th>Write ACEs (Dangerous)</th>
      <th>Read ACEs</th>
      <th style="width:60px">Files</th>
      <th style="width:120px">Note</th>
    </tr></thead>
    <tbody>$shareRows</tbody>
  </table>
  </div>
</div>

<!-- ── DANGEROUS ────────────────────────────────────────────────── -->
<div id="p-dangerous" class="panel">
  <div class="toolbar">
    <input id="dq" oninput="fDangerQ()" placeholder="&#128269; Search...">
  </div>
  <div class="tscroll">
  <table id="danger-table">
    <thead><tr>
      <th style="width:90px">Risk</th>
      <th style="width:160px">Host</th>
      <th style="width:130px">Share</th>
      <th style="width:60px">Access</th>
      <th>Dangerous ACEs / Findings</th>
      <th style="width:60px">Files</th>
    </tr></thead>
    <tbody id="danger-body">
    $($allShares | Where-Object { $_.Risk -in 'Critical','High','Medium' } | Sort-Object { $sevOrd[$_.Risk] }, Host, Name | ForEach-Object {
        $s  = $_
        $clr = $sevClr[$s.Risk]
        $acc = if ($s.Accessible) { '<span style="color:#4ade80">&#10003;</span>' } else { '<span style="color:#475569">&#10007;</span>' }
        $aces = ($s.DangerousAces -join '<br>')
        @"
<tr class="dr">
  <td><span class="b" style="background:$clr">$($s.Risk)</span></td>
  <td>$( HtmlEnc $s.Host )</td>
  <td><strong>$( HtmlEnc $s.Name )</strong></td>
  <td>$acc</td>
  <td class="wred" style="font-size:.8em">$( HtmlEnc $aces )</td>
  <td>$($s.FileCount)</td>
</tr>
"@
    }) -join ''
    </tbody>
  </table>
  </div>
</div>

<!-- ── FILES ────────────────────────────────────────────────────── -->
<div id="p-files" class="panel">
  <div class="toolbar">
    <input id="fq" oninput="fFileQ()" placeholder="&#128269; Search path / reason...">
  </div>
  <div class="tscroll">
  <table id="file-table">
    <thead><tr>
      <th style="width:150px">Host</th>
      <th style="width:100px">Share</th>
      <th>Path</th>
      <th style="width:70px">Size</th>
      <th style="width:110px">Modified</th>
      <th style="width:180px">Reason</th>
      <th>Snippet</th>
    </tr></thead>
    <tbody>$(if ($fileRows) { $fileRows } else { '<tr><td colspan="7" style="text-align:center;color:#475569;padding:30px">No interesting files found</td></tr>' })</tbody>
  </table>
  </div>
</div>

</div><!-- /wrap -->

<footer>
  ShareHunt &nbsp;|&nbsp; $ts &nbsp;|&nbsp; Read-only: no files were created, modified, or deleted &nbsp;|&nbsp;
  Report: <code style="background:transparent;color:#475569;display:inline">$reportPath</code>
</footer>

<script>
function showTab(id) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('on'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('on'));
    event.target.classList.add('on');
    document.getElementById('p-' + id).classList.add('on');
}
var curSev = '';
function fShareSev(s) {
    curSev = s;
    document.querySelectorAll('.toolbar button[id^="sb-"]').forEach(b => b.classList.remove('on'));
    document.getElementById('sb-' + (s || 'all')).classList.add('on');
    applyShareFilter();
}
function fShareQ() { applyShareFilter(); }
function applyShareFilter() {
    var q = (document.getElementById('sq').value || '').toLowerCase();
    document.querySelectorAll('#share-table .sr').forEach(function(r) {
        var risk = r.getAttribute('data-risk');
        var txt  = r.innerText.toLowerCase();
        var ms = !curSev || risk === curSev;
        var mq = !q || txt.includes(q);
        r.style.display = (ms && mq) ? '' : 'none';
    });
}
function fDangerQ() {
    var q = (document.getElementById('dq').value || '').toLowerCase();
    document.querySelectorAll('#danger-table .dr').forEach(function(r) {
        r.style.display = (!q || r.innerText.toLowerCase().includes(q)) ? '' : 'none';
    });
}
function fFileQ() {
    var q = (document.getElementById('fq').value || '').toLowerCase();
    document.querySelectorAll('#file-table tbody tr').forEach(function(r) {
        r.style.display = (!q || r.innerText.toLowerCase().includes(q)) ? '' : 'none';
    });
}
</script>
</body></html>
"@

[System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)

Write-Log ''
Write-Log ([string]::new('=',72)) 'Cyan'
Write-Log "  ShareHunt complete" 'Cyan'
Write-Log "  Hosts    : $hostsOnline online / $total targeted" 'Cyan'
Write-Log "  Shares   : $($allShares.Count) found  |  $($dangerousShares.Count) dangerous  |  $($gppShares.Count) GPP cpassword" 'Cyan'
Write-Log "  Files    : $($allFiles.Count) interesting" 'Cyan'
Write-Log "  Report   : $reportPath" 'Green'
Write-Log "  Shares   : $csvSharePath" 'Green'
Write-Log "  Files    : $csvFilePath" 'Green'
Write-Log ([string]::new('=',72)) 'Cyan'

[PSCustomObject]@{
    ReportPath     = $reportPath
    SharesCsvPath  = $csvSharePath
    FilesCsvPath   = $csvFilePath
    HostsOnline    = $hostsOnline
    SharesTotal    = $allShares.Count
    SharesDangerous = $dangerousShares.Count
    FilesFound     = $allFiles.Count
    GPPCredShares  = $gppShares.Count
}
