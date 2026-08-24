<#
.SYNOPSIS
    Invoke-SOCScan - Native Windows internal network scanner for SOC detection validation.

.DESCRIPTION
    A purple-team demonstration tool that performs host discovery and TCP port scanning
    using only built-in .NET / Windows capabilities - no nmap, no external binary, no
    install, and no local administrator rights required.

    Purpose: to demonstrate during a SOC uplift exercise that blocking or signaturing a
    named tool (e.g. nmap.exe) does NOT stop internal network reconnaissance. The network
    fingerprint produced here - one source touching many hosts and/or many ports in a short
    window - is the SAME signature a real intrusion produces, and SHOULD trigger the same
    detections. If it does not, that gap is the finding.

    The tool is deliberately "loud" and deliberately identifiable. Every probe carries a
    correlation tag so the blue team can locate this activity in their telemetry after the
    run and confirm (or disprove) that their controls saw it.

.NOTES
    Authorised security testing only. Run only against systems you are explicitly
    authorised to assess, within an agreed rules-of-engagement window.
    Author: Chaleit - Security Advisory & Offensive Services
    Safe by design: TCP connect + ICMP only. No exploitation. No writes to targets.

.PARAMETER Target
    What to scan. Accepts CIDR (10.0.0.0/24), dashed range (10.0.0.10-10.0.0.60 or
    10.0.0.10-60), a single IP, or a comma-separated mix of these.

.PARAMETER Ports
    Ports to scan. Accepts a profile name (top, windows, web, db, full), a comma list
    (22,80,445), a range (1-1024), or a mix (22,80,443,8000-8100). Default: top.

.PARAMETER ScanAll
    Scan every target regardless of discovery. By default only hosts that respond to
    discovery are port-scanned.

.PARAMETER Order
    Vertical (default) scans all ports on a host before moving on. Horizontal sweeps one
    port across all hosts before the next port - the classic, most detectable scan shape.
    Random shuffles the probe order to illustrate a basic evasion attempt.

.PARAMETER Throttle
    Concurrent probes. Higher = faster and louder. Default 64.

.PARAMETER DelayMs
    Per-probe delay in milliseconds inside each worker. Raise to slow the scan and test
    whether low-and-slow evades the SOC threshold. Default 0.

.PARAMETER TimeoutMs
    TCP/ICMP probe timeout in milliseconds. Default 1000.

.PARAMETER Grab
    Attempt a lightweight service banner grab on open ports.

.PARAMETER Tag
    Correlation marker embedded in HTTP probes and written to output, so the blue team can
    find this run in their logs. Default CHALEIT-SOC-DEMO.

.PARAMETER OutputDirectory
    Where to write the CSV/JSON result files. Default: the script directory.

.PARAMETER AllowPublic
    Permit scanning of non-RFC1918 (public) addresses. Off by default; the tool is
    internal-only unless you explicitly opt in.

.PARAMETER Force
    Skip the interactive authorisation prompt and the large-scope confirmation. Use only in
    an approved, scripted run.

.EXAMPLE
    .\Invoke-SOCScan.ps1 -Target 10.0.10.0/24 -Ports windows -Grab
    Discover live hosts on the /24, then scan the common Windows service ports and grab banners.

.EXAMPLE
    .\Invoke-SOCScan.ps1 -Target 10.0.10.0/24 -Ports 445 -Order Horizontal -ScanAll
    Sweep TCP/445 across the whole subnet - the loudest, clearest port-scan signature for a SOC to catch.

.EXAMPLE
    .\Invoke-SOCScan.ps1 -Target 10.0.10.5 -Ports 1-1024 -DelayMs 250
    Vertical scan of a single host, slowed down to test low-and-slow detection thresholds.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Ports = 'top',
    [switch]$ScanAll,
    [ValidateSet('Vertical', 'Horizontal', 'Random')][string]$Order = 'Vertical',
    [int]$Throttle = 64,
    [int]$DelayMs = 0,
    [int]$TimeoutMs = 1000,
    [switch]$Grab,
    [string]$Tag = 'CHALEIT-SOC-DEMO',
    [string]$OutputDirectory,
    [switch]$AllowPublic,
    [switch]$Force,
    [int]$MaxHosts = 2048
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ helpers

function ConvertTo-UInt32IP([string]$ip) {
    $bytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function ConvertFrom-UInt32IP([uint32]$value) {
    $bytes = [System.BitConverter]::GetBytes($value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Test-Rfc1918([string]$ip) {
    try { $v = ConvertTo-UInt32IP $ip } catch { return $false }
    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 (link-local), 127.0.0.0/8
    $ranges = @(
        @{ n = (ConvertTo-UInt32IP '10.0.0.0');    m = 8  },
        @{ n = (ConvertTo-UInt32IP '172.16.0.0');  m = 12 },
        @{ n = (ConvertTo-UInt32IP '192.168.0.0'); m = 16 },
        @{ n = (ConvertTo-UInt32IP '169.254.0.0'); m = 16 },
        @{ n = (ConvertTo-UInt32IP '127.0.0.0');   m = 8  }
    )
    foreach ($r in $ranges) {
        $mask = if ($r.m -eq 0) { [uint32]0 } else { [uint32](([uint64]0xFFFFFFFF -shl (32 - $r.m)) -band 0xFFFFFFFF) }
        if (($v -band $mask) -eq ($r.n -band $mask)) { return $true }
    }
    return $false
}

function Expand-Cidr([string]$cidr) {
    # Enumerate by small integer offsets from the network address. We never apply the
    # '..' range operator to raw uint32 IP values, because 172.16+/192.168 addresses
    # exceed Int32.MaxValue and would overflow.
    $parts = $cidr.Split('/')
    $prefix = [int]$parts[1]
    if ($prefix -lt 0 -or $prefix -gt 32) { throw "Invalid CIDR prefix: /$prefix" }
    $base = ConvertTo-UInt32IP $parts[0]
    $mask = if ($prefix -eq 0) { [uint32]0 } else { [uint32](([uint64]0xFFFFFFFF -shl (32 - $prefix)) -band 0xFFFFFFFF) }
    $network = [uint32]($base -band $mask)
    $total = [uint64][math]::Pow(2, 32 - $prefix)
    $out = New-Object System.Collections.Generic.List[string]
    if ($prefix -ge 31) {
        # /31 and /32: enumerate every address, no network/broadcast trimming
        for ($i = [uint64]0; $i -lt $total; $i++) { $out.Add((ConvertFrom-UInt32IP ([uint32]($network + $i)))) }
    }
    else {
        # usable hosts: network+1 .. network+total-2
        for ($i = [uint64]1; $i -le ($total - 2); $i++) { $out.Add((ConvertFrom-UInt32IP ([uint32]($network + $i)))) }
    }
    return $out
}

function Expand-Range([string]$range) {
    # supports 10.0.0.10-10.0.0.60  and  10.0.0.10-60
    $bits = $range.Split('-')
    $start = $bits[0].Trim()
    $endRaw = $bits[1].Trim()
    if ($endRaw -match '^\d{1,3}$') {
        $prefix = $start.Substring(0, $start.LastIndexOf('.') + 1)
        $endRaw = "$prefix$endRaw"
    }
    $s = ConvertTo-UInt32IP $start
    $e = ConvertTo-UInt32IP $endRaw
    if ($e -lt $s) { throw "Range end precedes start: $range" }
    $count = [uint64]$e - [uint64]$s
    $out = New-Object System.Collections.Generic.List[string]
    for ($i = [uint64]0; $i -le $count; $i++) { $out.Add((ConvertFrom-UInt32IP ([uint32]($s + $i)))) }
    return $out
}

function Expand-Target([string]$spec) {
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($chunk in ($spec -split ',')) {
        $c = $chunk.Trim()
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if ($c -match '/') { Expand-Cidr $c | ForEach-Object { $result.Add($_) } }
        elseif ($c -match '-') { Expand-Range $c | ForEach-Object { $result.Add($_) } }
        else { $null = [System.Net.IPAddress]::Parse($c); $result.Add($c) }
    }
    return ($result | Select-Object -Unique)
}

function Expand-Ports([string]$spec) {
    $profiles = @{
        top     = @(21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445, 464, 636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017)
        windows = @(53, 80, 88, 135, 139, 389, 443, 445, 464, 636, 3389, 5985, 5986, 9389)
        web     = @(80, 443, 8000, 8080, 8443, 8888)
        db      = @(1433, 1521, 3306, 5432, 6379, 9200, 27017)
        full    = (1..65535)
    }
    if ($profiles.ContainsKey($spec.ToLower())) { return $profiles[$spec.ToLower()] }

    $ports = New-Object System.Collections.Generic.List[int]
    foreach ($chunk in ($spec -split ',')) {
        $c = $chunk.Trim()
        if ($c -match '^\d+-\d+$') {
            $b = $c.Split('-'); ([int]$b[0]..[int]$b[1]) | ForEach-Object { $ports.Add($_) }
        }
        elseif ($c -match '^\d+$') { $ports.Add([int]$c) }
    }
    return ($ports | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Select-Object -Unique)
}

# service name lookup for readable output
$script:ServiceMap = @{
    21='ftp';22='ssh';23='telnet';25='smtp';53='dns';80='http';88='kerberos';110='pop3';111='rpcbind';
    135='msrpc';139='netbios-ssn';143='imap';389='ldap';443='https';445='smb';464='kpasswd';636='ldaps';
    993='imaps';995='pop3s';1433='mssql';1521='oracle';2049='nfs';3306='mysql';3389='rdp';5432='postgres';
    5900='vnc';5985='winrm-http';5986='winrm-https';6379='redis';8080='http-alt';8443='https-alt';
    9200='elasticsearch';9389='adws';27017='mongodb'
}

# ------------------------------------------------------------------ worker scriptblocks

$discoveryBlock = {
    param($ip, $timeoutMs, $tag)
    $alive = $false
    $method = ''
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $r = $p.Send($ip, $timeoutMs)
        if ($r.Status -eq 'Success') { $alive = $true; $method = 'icmp' }
    } catch { }
    if (-not $alive) {
        foreach ($tp in 445, 135, 139, 80, 443, 22, 3389) {
            try {
                $c = New-Object System.Net.Sockets.TcpClient
                $iar = $c.BeginConnect($ip, $tp, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne($timeoutMs, $false) -and $c.Connected) {
                    $alive = $true; $method = "tcp/$tp"; $c.Close(); break
                }
                $c.Close()
            } catch { }
        }
    }
    [pscustomobject]@{ Host = $ip; Alive = $alive; Method = $method }
}

$scanBlock = {
    param($ip, $port, $timeoutMs, $delayMs, $tag, $grab, $svc)
    if ($delayMs -gt 0) { Start-Sleep -Milliseconds $delayMs }
    $state = 'closed|filtered'
    $banner = ''
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($ip, $port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($timeoutMs, $false) -and $c.Connected) {
            $c.EndConnect($iar)
            $state = 'open'
            if ($grab) {
                try {
                    $stream = $c.GetStream()
                    $stream.ReadTimeout = 1500
                    if ($port -in 80, 8080, 8000, 8888) {
                        $req = "HEAD / HTTP/1.0`r`nHost: $ip`r`nUser-Agent: $tag`r`n`r`n"
                        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
                        $stream.Write($bytes, 0, $bytes.Length)
                    }
                    Start-Sleep -Milliseconds 250
                    if ($stream.DataAvailable) {
                        $buf = New-Object byte[] 1024
                        $n = $stream.Read($buf, 0, 1024)
                        if ($n -gt 0) {
                            $banner = ([System.Text.Encoding]::ASCII.GetString($buf, 0, $n) -replace '[\r\n]+', ' ').Trim()
                            if ($banner.Length -gt 160) { $banner = $banner.Substring(0, 160) }
                        }
                    }
                } catch { }
            }
        }
        $c.Close()
    } catch { $state = 'closed|filtered' }
    [pscustomobject]@{
        Host         = $ip
        Port         = $port
        State        = $state
        Service      = $svc
        Banner       = $banner
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
}

# generic runspace-pool executor (Windows PowerShell 5.1 compatible)
function Invoke-Pool {
    param($ScriptBlock, [object[]]$WorkItems, [int]$Throttle, [string]$Activity)
    $pool = [runspacefactory]::CreateRunspacePool(1, [math]::Max(1, $Throttle))
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]
    foreach ($item in $WorkItems) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ScriptBlock)
        foreach ($arg in $item) { [void]$ps.AddArgument($arg) }
        $jobs.Add([pscustomobject]@{ Pipe = $ps; Async = $ps.BeginInvoke() })
    }
    $results = New-Object System.Collections.Generic.List[object]
    $done = 0; $total = $jobs.Count
    foreach ($j in $jobs) {
        try { $j.Pipe.EndInvoke($j.Async) | ForEach-Object { $results.Add($_) } } catch { }
        $j.Pipe.Dispose()
        $done++
        if ($total -gt 0 -and ($done % 25 -eq 0 -or $done -eq $total)) {
            Write-Progress -Activity $Activity -Status "$done / $total" -PercentComplete (($done / $total) * 100)
        }
    }
    Write-Progress -Activity $Activity -Completed
    $pool.Close(); $pool.Dispose()
    return $results
}

# ------------------------------------------------------------------ banner / authorisation

$hostName = [System.Net.Dns]::GetHostName()
$srcIPs = @()
try {
    $srcIPs = [System.Net.Dns]::GetHostAddresses($hostName) |
        Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.ToString() }
} catch { }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Invoke-SOCScan  -  SOC detection-validation scanner (Chaleit)"   -ForegroundColor Cyan
Write-Host " Native Windows tooling. No nmap. No install. No admin required." -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host (" Source host : {0}" -f $hostName)
Write-Host (" Source IPs  : {0}" -f ($srcIPs -join ', '))
Write-Host (" Run user    : {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Host (" Correlation : {0}" -f $Tag)
Write-Host ""
Write-Host " AUTHORISED USE ONLY. This tool generates network activity that is" -ForegroundColor Yellow
Write-Host " intended to trigger security alerts. Run it only against systems"  -ForegroundColor Yellow
Write-Host " you are explicitly authorised to test, inside an agreed window."   -ForegroundColor Yellow
Write-Host ""

# expand scope
$targets = @(Expand-Target $Target)
$portList = @(Expand-Ports $Ports)
if ($targets.Count -eq 0) { throw "No valid targets parsed from '$Target'." }
if ($portList.Count -eq 0) { throw "No valid ports parsed from '$Ports'." }

# RFC1918 guard
$public = @($targets | Where-Object { -not (Test-Rfc1918 $_) })
if ($public.Count -gt 0 -and -not $AllowPublic) {
    Write-Host (" REFUSING: {0} target(s) are outside private/internal ranges." -f $public.Count) -ForegroundColor Red
    Write-Host (" Example: {0}. Re-run with -AllowPublic only if these are in scope." -f (($public | Select-Object -First 3) -join ', ')) -ForegroundColor Red
    throw "Public targets present and -AllowPublic not set. Aborting."
}

Write-Host (" Targets     : {0} host(s)" -f $targets.Count)
Write-Host (" Ports       : {0} port(s) [{1}]" -f $portList.Count, $Ports)
Write-Host (" Order       : {0}   Throttle: {1}   DelayMs: {2}   TimeoutMs: {3}" -f $Order, $Throttle, $DelayMs, $TimeoutMs)
Write-Host ""

# scope-size guard
if ($targets.Count -gt $MaxHosts -and -not $Force) {
    throw ("Scope is {0} hosts, above the {1}-host safety limit. Re-run with -Force to proceed." -f $targets.Count, $MaxHosts)
}

# authorisation prompt
if (-not $Force) {
    $ack = Read-Host " Type YES to confirm you are authorised to scan this scope"
    if ($ack -ne 'YES') { Write-Host " Aborted by operator." -ForegroundColor Red; return }
}

# ------------------------------------------------------------------ discovery

$startUtc = (Get-Date).ToUniversalTime()
$liveHosts = $targets

if (-not $ScanAll) {
    Write-Host ""
    Write-Host " [*] Phase 1: host discovery (ICMP + TCP ping)..." -ForegroundColor Green
    $discWork = @($targets | ForEach-Object { , @($_, $TimeoutMs, $Tag) })
    $disc = Invoke-Pool -ScriptBlock $discoveryBlock -WorkItems $discWork -Throttle $Throttle -Activity 'Host discovery'
    $liveHosts = @($disc | Where-Object { $_.Alive } | ForEach-Object { $_.Host })
    Write-Host ("     {0} of {1} hosts responded to discovery." -f $liveHosts.Count, $targets.Count) -ForegroundColor Green
    if ($liveHosts.Count -eq 0) {
        Write-Host "     No live hosts. Use -ScanAll to port-scan regardless of discovery." -ForegroundColor Yellow
        return
    }
}

# ------------------------------------------------------------------ port scan

Write-Host ""
Write-Host (" [*] Phase 2: TCP connect scan ({0} order)..." -f $Order) -ForegroundColor Green

# build work list honouring scan order
$work = New-Object System.Collections.Generic.List[object]
if ($Order -eq 'Horizontal') {
    foreach ($p in $portList) {
        foreach ($h in $liveHosts) {
            $work.Add(@($h, $p, $TimeoutMs, $DelayMs, $Tag, [bool]$Grab, [string]$script:ServiceMap[$p]))
        }
    }
}
else {
    foreach ($h in $liveHosts) {
        foreach ($p in $portList) {
            $work.Add(@($h, $p, $TimeoutMs, $DelayMs, $Tag, [bool]$Grab, [string]$script:ServiceMap[$p]))
        }
    }
}
$workItems = $work.ToArray()
if ($Order -eq 'Random') {
    $workItems = @($workItems | Sort-Object { Get-Random })
}

$scan = Invoke-Pool -ScriptBlock $scanBlock -WorkItems $workItems -Throttle $Throttle -Activity 'Port scan'
$open = @($scan | Where-Object { $_.State -eq 'open' } | Sort-Object -Property @({ ConvertTo-UInt32IP $_.Host }, 'Port'))
$endUtc = (Get-Date).ToUniversalTime()

# ------------------------------------------------------------------ output

Write-Host ""
Write-Host " [*] Open services found:" -ForegroundColor Green
if ($open.Count -gt 0) {
    $open | Format-Table Host, Port, Service, State, Banner -AutoSize | Out-Host
}
else {
    Write-Host "     None open in scanned scope." -ForegroundColor Yellow
}

if (-not $OutputDirectory) { $OutputDirectory = $PSScriptRoot }
if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$stamp = $startUtc.ToString('yyyyMMdd-HHmmss')
$csvPath = Join-Path $OutputDirectory "SOCScan_$stamp.csv"
$jsonPath = Join-Path $OutputDirectory "SOCScan_$stamp.json"
$open | Export-Csv -Path $csvPath -NoTypeInformation
$open | ConvertTo-Json -Depth 4 | Out-File -FilePath $jsonPath -Encoding UTF8

# correlation summary - what the blue team should look for
$distinctHosts = @($scan | Select-Object -ExpandProperty Host -Unique).Count
$attempts = $scan.Count
$distinctPorts = @($scan | Select-Object -ExpandProperty Port -Unique).Count
$durationSec = [math]::Round(($endUtc - $startUtc).TotalSeconds, 1)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " CORRELATION SUMMARY  (hand this to the SOC to hunt against)"      -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host (" Correlation tag       : {0}" -f $Tag)
Write-Host (" Source host / user    : {0}  ({1}\{2})" -f $hostName, $env:USERDOMAIN, $env:USERNAME)
Write-Host (" Source IP(s)          : {0}" -f ($srcIPs -join ', '))
Write-Host (" Initiating process    : powershell.exe  (NOT nmap.exe)")
Write-Host (" Window (UTC)          : {0}  ->  {1}  ({2}s)" -f $startUtc.ToString('o'), $endUtc.ToString('o'), $durationSec)
Write-Host (" Connection attempts   : {0}" -f $attempts)
Write-Host (" Distinct dst hosts    : {0}" -f $distinctHosts)
Write-Host (" Distinct dst ports    : {0}" -f $distinctPorts)
Write-Host (" Open services found   : {0}" -f $open.Count)
Write-Host (" Expected signature    : one source -> many hosts/ports, high failed-conn ratio")
Write-Host (" ATT&CK                : T1046 Network Service Discovery, T1018 Remote System Discovery")
Write-Host ""
Write-Host (" Results CSV  : {0}" -f $csvPath)
Write-Host (" Results JSON : {0}" -f $jsonPath)
Write-Host ""
Write-Host " Now ask the SOC: did an alert fire for this activity? If they were" -ForegroundColor Yellow
Write-Host " relying on blocking nmap.exe, the answer is very likely no."         -ForegroundColor Yellow
Write-Host ""
