#Requires -Version 5.1
<#
.SYNOPSIS
    BloodHound-compatible AD collector -- produces SharpHound v4 JSON files
    for import into BloodHound / Neo4j and analysis with PlumHound.
    No SharpHound.exe or BloodHound agent required.

.DESCRIPTION
    Collects Users, Computers, Groups, Domains, GPOs and OUs with their ACL
    edges.  Output is a ZIP archive in SharpHound v4 format ready to drag into
    the BloodHound "Upload Data" dialog, or individual JSON files for direct
    Neo4j ingest / PlumHound task runs. Directory data is queried with the
    inbox System.DirectoryServices ADSI/LDAP APIs. The ActiveDirectory and
    GroupPolicy PowerShell modules (RSAT) are not required.

.PARAMETER DomainController
    FQDN or IP of a DC to query.  Omit to use automatic discovery.

.PARAMETER Domain
    DNS name of the target domain.  Omit to use the current computer's domain.

.PARAMETER Credential
    PSCredential for cross-domain or explicit auth.

.PARAMETER OutputPath
    Folder where JSON files and ZIP are written.
    Default: $env:USERPROFILE\Documents\BHCollect

.PARAMETER NoCompress
    Write raw JSON files only; skip ZIP creation.

.EXAMPLE
    .\Invoke-BHCollector-NoRSAT.ps1 -DomainController dc01.corp.local
    .\Invoke-BHCollector-NoRSAT.ps1 -Domain corp.local
    .\Invoke-BHCollector-NoRSAT.ps1 -DomainController dc01 -Credential (Get-Credential) -OutputPath C:\Temp\BH
#>
[CmdletBinding()]
param(
    [string]$DomainController = '',
    [string]$Domain           = '',
    [PSCredential]$Credential,
    [string]$OutputPath       = "$env:USERPROFILE\Documents\BHCollect",
    [switch]$NoCompress
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$VerbosePreference     = 'Continue'

# ---------------------------------------------------------------------------
# ACE / schema GUIDs
# ---------------------------------------------------------------------------
$GUID_GetChanges         = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GetChangesAll      = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GetChangesFiltered = [Guid]'89e95b76-444d-4c62-991a-0facbeda640c'
$GUID_ForceChangePwd     = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$GUID_MemberAttr         = [Guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'   # member write = AddMember
$GUID_AllowedToActAttr   = [Guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'  # msDS-AllowedToActOnBehalfOfOtherIdentity
$GUID_Empty              = [Guid]::Empty

# Resolved from AD schema at runtime; includes legacy and Windows LAPS attrs.
$script:LAPSGuid = @()

# ---------------------------------------------------------------------------
# SID-to-object-type lookup built while enumerating objects
# ---------------------------------------------------------------------------
$script:SidMap = [System.Collections.Hashtable]::new()

# ---------------------------------------------------------------------------
# Helper -- build connection splatting hashtable.  These keys are consumed by
# the local LDAP compatibility functions below; no ActiveDirectory module is
# imported or required.
# ---------------------------------------------------------------------------
function Get-DcParam {
    $p = @{}
    if ($DomainController) { $p['Server'] = $DomainController }
    elseif ($Domain)       { $p['Server'] = $Domain }
    if ($Credential)       { $p['Credential'] = $Credential }
    return $p
}

# ---------------------------------------------------------------------------
# Native LDAP / ADSI compatibility layer
# ---------------------------------------------------------------------------
$script:LdapServer = ''
$script:DefaultNC  = ''
$script:ConfigNC   = ''
$script:SchemaNC   = ''

function New-LdapEntry {
    param([string]$Path, [PSCredential]$BindCredential)
    if ($BindCredential) {
        $net = $BindCredential.GetNetworkCredential()
        $bindUser = $net.UserName
        if ($net.Domain -and $bindUser -notmatch '[@\\]') { $bindUser = "$($net.Domain)\$bindUser" }
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path, $bindUser, $net.Password,
            [System.DirectoryServices.AuthenticationTypes]::Secure)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function Get-LdapPath {
    param([string]$DN)
    $prefix = if ($script:LdapServer) { "LDAP://$($script:LdapServer)/" } else { 'LDAP://' }
    return $prefix + ($DN -replace '/', '\/')
}

function Get-NltestDC {
    param([string]$DnsDomain)
    if (-not $DnsDomain) { return '' }
    try {
        $lines = & "$env:SystemRoot\System32\nltest.exe" "/dsgetdc:$DnsDomain" 2>$null
        foreach ($line in @($lines)) {
            if ($line -match '^\s*DC:\s+\\\\([^\s]+)') { return $Matches[1].TrimEnd('.') }
        }
    } catch {}
    return ''
}

function Initialize-LdapContext {
    $domainHint = $Domain
    if (-not $domainHint) { $domainHint = $env:USERDNSDOMAIN }
    if (-not $domainHint) {
        try { $domainHint = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName } catch {}
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($DomainController) { $candidates.Add($DomainController) }
    if (-not $DomainController -and $domainHint) {
        $nlDc = Get-NltestDC $domainHint
        if ($nlDc) { $candidates.Add($nlDc) }
        $candidates.Add($domainHint)
    }
    if (-not $DomainController) {
        try {
            $dotNetDc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
            if ($dotNetDc) { $candidates.Add($dotNetDc) }
        } catch {}
        $candidates.Add('') # ADSI's built-in DC locator
    }

    $lastError = $null
    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        $rootPath = if ($candidate) { "LDAP://$candidate/RootDSE" } else { 'LDAP://RootDSE' }
        $root = $null
        try {
            $root = New-LdapEntry -Path $rootPath -BindCredential $Credential
            $script:DefaultNC = [string]$root.Properties['defaultNamingContext'].Value
            if (-not $script:DefaultNC) { throw 'RootDSE did not return defaultNamingContext' }
            $script:ConfigNC   = [string]$root.Properties['configurationNamingContext'].Value
            $script:SchemaNC   = [string]$root.Properties['schemaNamingContext'].Value
            $script:LdapServer = $candidate
            return
        } catch {
            $lastError = $_
        } finally {
            if ($root) { $root.Dispose() }
        }
    }
    throw "Unable to bind to Active Directory with ADSI/LDAP. Domain hint: '$domainHint'. Last error: $lastError"
}

function Get-LdapValues {
    param($Result, [string]$Name)
    if ($null -eq $Result -or -not $Result.Properties.Contains($Name)) { return @() }
    return @($Result.Properties[$Name])
}

function Get-LdapValue {
    param($Result, [string]$Name)
    $values = @(Get-LdapValues $Result $Name)
    if ($values.Count -eq 0) { return $null }
    return $values[0]
}

function Get-LdapRangedValues {
    param($InitialResult, [string]$DN, [string]$Attribute)
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($value in @(Get-LdapValues $InitialResult $Attribute)) { $all.Add($value) }
    if ($all.Count -gt 0) { return @($all) }

    $result = $InitialResult
    while ($result) {
        $rangeName = @($result.Properties.PropertyNames | Where-Object { $_ -like "$Attribute;range=*" } | Select-Object -First 1)
        if ($rangeName.Count -eq 0) { break }
        foreach ($value in @($result.Properties[$rangeName[0]])) { $all.Add($value) }
        if ($rangeName[0] -match ';range=\d+-(\d+)$') {
            $next = [int]$Matches[1] + 1
            $nextRows = @(Search-Ldap '(objectClass=*)' $DN @("$Attribute;range=$next-*") Base)
            if ($nextRows.Count -eq 0) { break }
            $result = $nextRows[0]
        } else {
            break # terminal range ends in '*'
        }
    }
    return @($all)
}

function Convert-LdapSid {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [System.Security.Principal.SecurityIdentifier]) { return $Value }
        return New-Object System.Security.Principal.SecurityIdentifier([byte[]]$Value, 0)
    } catch { return $null }
}

function Convert-LdapGuid {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [Guid]) { return $Value }
        return New-Object Guid(,[byte[]]$Value)
    } catch { return $null }
}

function Convert-LdapSecurityDescriptor {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$Value)
        return $sd
    } catch { return $null }
}

function Search-Ldap {
    param(
        [string]$LDAPFilter,
        [string]$SearchBase = $script:DefaultNC,
        [string[]]$Properties = @(),
        [System.DirectoryServices.SearchScope]$Scope = [System.DirectoryServices.SearchScope]::Subtree,
        [switch]$SecurityDescriptor
    )
    $entry = New-LdapEntry -Path (Get-LdapPath $SearchBase) -BindCredential $Credential
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $LDAPFilter
    $searcher.SearchScope = $Scope
    $searcher.PageSize = 1000
    $searcher.SizeLimit = 0
    $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
    if ($SecurityDescriptor) {
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner
    }
    foreach ($prop in $Properties) { [void]$searcher.PropertiesToLoad.Add($prop) }
    $found = $null
    try {
        $found = $searcher.FindAll()
        return @($found)
    } finally {
        if ($found) { $found.Dispose() }
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function Convert-LdapAccount {
    param($Result, [ValidateSet('User','Computer','Group','OU','Object')]$Kind)
    $uac = [int](Get-LdapValue $Result 'userAccountControl')
    $sid = Convert-LdapSid (Get-LdapValue $Result 'objectSid')
    $sidHistory = @(Get-LdapValues $Result 'sIDHistory' | ForEach-Object { Convert-LdapSid $_ })
    $obj = [ordered]@{
        SamAccountName = [string](Get-LdapValue $Result 'sAMAccountName')
        UserPrincipalName = [string](Get-LdapValue $Result 'userPrincipalName')
        DistinguishedName = [string](Get-LdapValue $Result 'distinguishedName')
        ObjectSID = $sid
        ObjectGUID = Convert-LdapGuid (Get-LdapValue $Result 'objectGUID')
        Enabled = (($uac -band 0x2) -eq 0)
        AdminCount = Get-LdapValue $Result 'adminCount'
        Description = [string](Get-LdapValue $Result 'description')
        DisplayName = [string](Get-LdapValue $Result 'displayName')
        Title = [string](Get-LdapValue $Result 'title')
        HomeDirectory = [string](Get-LdapValue $Result 'homeDirectory')
        PasswordNeverExpires = (($uac -band 0x10000) -ne 0)
        PasswordNotRequired = (($uac -band 0x20) -ne 0)
        DoesNotRequirePreAuth = (($uac -band 0x400000) -ne 0)
        ServicePrincipalName = @(Get-LdapValues $Result 'servicePrincipalName')
        SIDHistory = $sidHistory
        LastLogon = Get-LdapValue $Result 'lastLogon'
        LastLogonTimeStamp = Get-LdapValue $Result 'lastLogonTimestamp'
        PasswordLastSet = Get-LdapValue $Result 'pwdLastSet'
        WhenCreated = Get-LdapValue $Result 'whenCreated'
        TrustedForDelegation = (($uac -band 0x80000) -ne 0)
        TrustedToAuthForDelegation = (($uac -band 0x1000000) -ne 0)
        'msDS-AllowedToDelegateTo' = @(Get-LdapValues $Result 'msDS-AllowedToDelegateTo')
        PrimaryGroupID = Get-LdapValue $Result 'primaryGroupID'
        userAccountControl = $uac
        DNSHostName = [string](Get-LdapValue $Result 'dNSHostName')
        OperatingSystem = [string](Get-LdapValue $Result 'operatingSystem')
        OperatingSystemVersion = [string](Get-LdapValue $Result 'operatingSystemVersion')
        'msDS-AllowedToActOnBehalfOfOtherIdentity' = Get-LdapValue $Result 'msDS-AllowedToActOnBehalfOfOtherIdentity'
        'ms-Mcs-AdmPwdExpirationTime' = Get-LdapValue $Result 'ms-Mcs-AdmPwdExpirationTime'
        'msLAPS-PasswordExpirationTime' = Get-LdapValue $Result 'msLAPS-PasswordExpirationTime'
        Members = @(Get-LdapValues $Result 'member')
        GroupScope = Get-LdapValue $Result 'groupType'
        GroupCategory = Get-LdapValue $Result 'groupType'
        Name = [string](Get-LdapValue $Result 'name')
        gpLink = [string](Get-LdapValue $Result 'gPLink')
        gPOptions = [int](Get-LdapValue $Result 'gPOptions')
        objectClass = @(Get-LdapValues $Result 'objectClass')
        nTSecurityDescriptor = Convert-LdapSecurityDescriptor (Get-LdapValue $Result 'nTSecurityDescriptor')
        schemaIDGUID = Convert-LdapGuid (Get-LdapValue $Result 'schemaIDGUID')
    }
    return [PSCustomObject]$obj
}

# The following query functions replace the AD/GroupPolicy cmdlets used by the
# original collector. All directory access is handled by ADSI.
function Get-LdapRootDSE { param($Server, $Credential) return [PSCustomObject]@{ schemaNamingContext = $script:SchemaNC; defaultNamingContext = $script:DefaultNC; configurationNamingContext = $script:ConfigNC } }

function Get-LdapObject {
    param([string]$Identity, [string]$SearchBase, [string]$LDAPFilter = '(objectClass=*)', [string[]]$Properties, $Server, $Credential)
    $attrs = @('objectClass','distinguishedName')
    foreach ($property in @($Properties)) {
        $attrs += switch ($property) {
            'ObjectSID'  { 'objectSid' }
            'ObjectGUID' { 'objectGUID' }
            'Members'    { 'member' }
            default      { $property }
        }
    }
    if ($Identity) {
        $rows = @(Search-Ldap -LDAPFilter '(objectClass=*)' -SearchBase $Identity -Properties $attrs -Scope Base -SecurityDescriptor:($Properties -contains 'nTSecurityDescriptor'))
    } else {
        $rows = @(Search-Ldap -LDAPFilter $LDAPFilter -SearchBase $SearchBase -Properties $attrs -SecurityDescriptor:($Properties -contains 'nTSecurityDescriptor'))
    }
    foreach ($row in $rows) { Convert-LdapAccount $row 'Object' }
}

function Find-LdapUser {
    param($Filter, [string[]]$Properties, $Server, $Credential)
    $attrs = @('sAMAccountName','userPrincipalName','distinguishedName','objectSid','adminCount',
        'description','displayName','title','homeDirectory','servicePrincipalName','sIDHistory',
        'lastLogon','lastLogonTimestamp','pwdLastSet','whenCreated','msDS-AllowedToDelegateTo',
        'primaryGroupID','userAccountControl','objectClass','objectCategory')
    foreach ($row in @(Search-Ldap '(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))' $script:DefaultNC $attrs)) { Convert-LdapAccount $row 'User' }
}

function Find-LdapComputer {
    param($Filter, [string[]]$Properties, $Server, $Credential)
    $attrs = @('sAMAccountName','dNSHostName','operatingSystem','operatingSystemVersion',
        'distinguishedName','objectSid','description','adminCount','msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity','sIDHistory','lastLogon','lastLogonTimestamp',
        'pwdLastSet','whenCreated','primaryGroupID','servicePrincipalName','userAccountControl',
        'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime','objectClass','objectCategory')
    foreach ($row in @(Search-Ldap '(objectCategory=computer)' $script:DefaultNC $attrs)) { Convert-LdapAccount $row 'Computer' }
}

function Find-LdapGroup {
    param($Filter, [string[]]$Properties, $Server, $Credential)
    $attrs = @('sAMAccountName','distinguishedName','objectSid','description','adminCount',
        'whenCreated','member','groupType','objectClass','objectCategory')
    foreach ($row in @(Search-Ldap '(objectCategory=group)' $script:DefaultNC $attrs)) {
        $group = Convert-LdapAccount $row 'Group'
        $group.Members = @(Get-LdapRangedValues -InitialResult $row -DN $group.DistinguishedName -Attribute 'member')
        $group
    }
}

function Find-LdapOrganizationalUnit {
    param($Filter, [string[]]$Properties, $Server, $Credential)
    $attrs = @('distinguishedName','name','description','whenCreated','gPLink','gPOptions',
        'objectGUID','objectClass','objectCategory')
    foreach ($row in @(Search-Ldap '(objectCategory=organizationalUnit)' $script:DefaultNC $attrs)) { Convert-LdapAccount $row 'OU' }
}

function Get-LdapDomain {
    param($Server, $Credential)
    $attrs = @('distinguishedName','objectSid','name','gPLink','msDS-Behavior-Version','whenCreated')
    $row = @(Search-Ldap '(objectClass=domainDNS)' $script:DefaultNC $attrs Base)[0]
    if (-not $row) { throw "Domain object not found at $($script:DefaultNC)" }
    $sid = Convert-LdapSid (Get-LdapValue $row 'objectSid')
    $dnsRoot = (($script:DefaultNC -split ',') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
    $mode = Get-LdapValue $row 'msDS-Behavior-Version'
    if ($null -eq $mode) { $mode = 0 }
    return [PSCustomObject]@{
        DNSRoot = $dnsRoot
        DistinguishedName = $script:DefaultNC
        DomainSID = $sid
        DomainMode = [int]$mode
        LinkedGroupPolicyObjects = @((Get-LdapValue $row 'gPLink'))
        WhenCreated = Get-LdapValue $row 'whenCreated'
    }
}

function Find-LdapTrust {
    param($Filter, $Server, $Credential)
    $attrs = @('name','flatName','securityIdentifier','trustDirection','trustType','trustAttributes')
    foreach ($row in @(Search-Ldap '(objectClass=trustedDomain)' "CN=System,$($script:DefaultNC)" $attrs OneLevel)) {
        $directionValue = [int](Get-LdapValue $row 'trustDirection')
        $typeValue = [int](Get-LdapValue $row 'trustType')
        $attributes = [int](Get-LdapValue $row 'trustAttributes')
        $direction = switch ($directionValue) { 1 { 'Inbound' } 2 { 'Outbound' } 3 { 'Bidirectional' } default { 'Disabled' } }
        $trustType = if ($typeValue -eq 3) {
            'MIT'
        } elseif (($attributes -band 0x8) -ne 0) {
            'Forest'
        } elseif (($attributes -band 0x20) -ne 0) {
            'ParentChild'
        } elseif ($typeValue -eq 1 -or $typeValue -eq 2) {
            'External'
        } else {
            'Unknown'
        }
        [PSCustomObject]@{
            Name = [string](Get-LdapValue $row 'name')
            Direction = $direction
            SecurityIdentifier = Convert-LdapSid (Get-LdapValue $row 'securityIdentifier')
            IsTransitive = (($attributes -band 0x1) -eq 0)
            TrustType = $trustType
            SIDFilteringQuarantined = (($attributes -band 0x4) -ne 0)
        }
    }
}

function Find-LdapGPO {
    param([switch]$All, $Server, $Credential)
    $base = "CN=Policies,CN=System,$($script:DefaultNC)"
    $attrs = @('name','displayName','description','whenCreated','gPCFileSysPath')
    foreach ($row in @(Search-Ldap '(objectClass=groupPolicyContainer)' $base $attrs OneLevel)) {
        $rawName = [string](Get-LdapValue $row 'name')
        $guidText = $rawName.Trim('{','}')
        [PSCustomObject]@{
            Id = [Guid]$guidText
            DisplayName = [string](Get-LdapValue $row 'displayName')
            Description = [string](Get-LdapValue $row 'description')
            CreationTime = Get-LdapValue $row 'whenCreated'
            GpcFileSysPath = [string](Get-LdapValue $row 'gPCFileSysPath')
        }
    }
}

# ---------------------------------------------------------------------------
# Helper -- FileTime (100-ns intervals since 1601) to Unix epoch seconds
# ---------------------------------------------------------------------------
function ConvertTo-Unix {
    param($FileTimeVal)
    if ($null -eq $FileTimeVal -or $FileTimeVal -le 0) { return -1 }
    try { return [int64]([DateTime]::FromFileTimeUtc([int64]$FileTimeVal) - [DateTime]'1970-01-01').TotalSeconds }
    catch { return -1 }
}

# ---------------------------------------------------------------------------
# Helper -- DateTime to Unix epoch seconds
# ---------------------------------------------------------------------------
function DateTo-Unix {
    param($dt)
    if ($null -eq $dt) { return -1 }
    try {
        if ($dt -isnot [DateTime]) {
            $text = [string]$dt
            if ($text -match '^\d{14}(?:\.\d+)?Z$') {
                $dt = [DateTime]::ParseExact(
                    $text.Substring(0, 14),
                    'yyyyMMddHHmmss',
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                        [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            } else {
                $dt = [DateTime]::Parse(
                    $text,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
            }
        }
        return [int64](($dt.ToUniversalTime()) - [DateTime]'1970-01-01').TotalSeconds
    }
    catch { return -1 }
}

# ---------------------------------------------------------------------------
# Helper -- Add SID -> type to global map (idempotent)
# ---------------------------------------------------------------------------
function Register-Sid {
    param([string]$Sid, [string]$Type)
    if (-not $Sid) { return }
    if (-not $script:SidMap.Contains($Sid)) { $script:SidMap[$Sid] = $Type }
}

# ---------------------------------------------------------------------------
# Helper -- Resolve SID string to BloodHound object type
# ---------------------------------------------------------------------------
function Get-SidType {
    param([string]$Sid)
    if (-not $Sid) { return 'Unknown' }
    # BUILTIN / well-known groups
    if ($Sid -match '^S-1-5-32-|^S-1-1-0$|^S-1-5-11$|^S-1-5-9$') { return 'Group' }
    # SYSTEM / Creator Owner
    if ($Sid -match '^S-1-5-18$|^S-1-3-0$') { return 'User' }
    # Well-known domain groups by RID
    $ridPart = ($Sid -split '-')[-1]
    $rid = 0
    if ([int]::TryParse($ridPart, [ref]$rid)) {
        if ($rid -ge 512 -and $rid -le 522) { return 'Group' }
    }
    if ($script:SidMap.Contains($Sid)) { return $script:SidMap[$Sid] }
    return 'Unknown'
}

# ---------------------------------------------------------------------------
# Helper -- Resolve SID or NT-name to SID string; returns '' on failure
# ---------------------------------------------------------------------------
function Resolve-ToSid {
    param([System.Security.Principal.IdentityReference]$Ref)
    try {
        $sid = $Ref.Translate([System.Security.Principal.SecurityIdentifier])
        return $sid.Value
    } catch {
        $v = $Ref.Value
        if ($v -match '^S-1-') { return $v }
        return ''
    }
}

# ---------------------------------------------------------------------------
# Helper -- Retrieve LAPS attribute GUID from schema
# ---------------------------------------------------------------------------
function Get-LAPSGuid {
    param([hashtable]$Dc)
    $guids = [System.Collections.Generic.List[Guid]]::new()
    try {
        $root    = Get-LdapRootDSE @Dc
        $schema  = $root.schemaNamingContext
        $attrs   = @(Get-LdapObject -SearchBase $schema `
                       -LDAPFilter '(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password)(lDAPDisplayName=msLAPS-EncryptedPassword))' `
                       -Properties schemaIDGUID @Dc
        )
        foreach ($attr in $attrs) {
            if ($attr -and $attr.schemaIDGUID) { $guids.Add([Guid]$attr.schemaIDGUID) }
        }
    } catch {}
    return @($guids)
}

# ---------------------------------------------------------------------------
# Core -- Convert one AD AccessRule to a BloodHound ACE hashtable or $null
# ---------------------------------------------------------------------------
function Convert-Ace {
    param(
        [System.Security.AccessControl.ActiveDirectoryAccessRule]$Ace,
        [string]$TargetType
    )

    if ($Ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { return $null }

    $principalSid = Resolve-ToSid -Ref $Ace.IdentityReference
    if (-not $principalSid) { return $null }
    # Skip SYSTEM, SELF
    if ($principalSid -match '^S-1-5-18$|^S-1-5-10$|^S-1-5-20$') { return $null }

    $rights  = $Ace.ActiveDirectoryRights
    $objType = $Ace.ObjectType

    $rightName = $null

    $hasGenericAll    = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)    -ne 0
    $hasWriteDacl     = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)     -ne 0
    $hasWriteOwner    = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)    -ne 0
    $hasGenericWrite  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0
    $hasExtended      = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0
    $hasWriteProp     = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0
    $hasSelf          = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::Self)          -ne 0
    $hasReadProp      = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)  -ne 0

    if ($hasGenericAll) {
        $rightName = 'GenericAll'
    } elseif ($hasWriteDacl) {
        $rightName = 'WriteDacl'
    } elseif ($hasWriteOwner) {
        $rightName = 'WriteOwner'
    } elseif ($hasGenericWrite) {
        $rightName = 'GenericWrite'
    } elseif ($hasExtended) {
        if ($objType -eq $GUID_GetChanges)         { $rightName = 'GetChanges' }
        elseif ($objType -eq $GUID_GetChangesAll)  { $rightName = 'GetChangesAll' }
        elseif ($objType -eq $GUID_GetChangesFiltered) { $rightName = 'GetChangesInFilteredSet' }
        elseif ($objType -eq $GUID_ForceChangePwd) { $rightName = 'ForceChangePassword' }
        elseif ($objType -eq $GUID_Empty)          { $rightName = 'AllExtendedRights' }
        elseif ($script:LAPSGuid -contains $objType) {
            $rightName = 'ReadLAPSPassword'
        }
    } elseif ($hasWriteProp) {
        if ($objType -eq $GUID_MemberAttr)       { $rightName = if ($TargetType -eq 'Group') { 'AddMember' } else { 'WriteProperty' } }
        elseif ($objType -eq $GUID_AllowedToActAttr) { $rightName = 'WriteAccountRestrictions' }
        elseif ($objType -eq $GUID_Empty)        { $rightName = 'GenericWrite' }
    } elseif ($hasSelf) {
        if ($objType -eq $GUID_MemberAttr) { $rightName = 'AddSelf' }
    } elseif ($hasReadProp) {
        if ($script:LAPSGuid -contains $objType) {
            $rightName = 'ReadLAPSPassword'
        }
    }

    if (-not $rightName) { return $null }

    $principalType = Get-SidType $principalSid

    $result = [ordered]@{
        PrincipalSID  = $principalSid
        PrincipalType = $principalType
        RightName     = $rightName
        IsInherited   = $Ace.IsInherited
    }
    return $result
}

# ---------------------------------------------------------------------------
# Core -- Retrieve ACEs for one AD object DN; returns List
# ---------------------------------------------------------------------------
function Get-BHAces {
    param([string]$DN, [string]$TargetType, [hashtable]$Dc)
    $list = [System.Collections.Generic.List[object]]::new()
    try {
        $obj = Get-LdapObject -Identity $DN -Properties nTSecurityDescriptor @Dc
        if ($null -eq $obj -or $null -eq $obj.nTSecurityDescriptor) { return $list }
        foreach ($ace in $obj.nTSecurityDescriptor.Access) {
            $bh = Convert-Ace -Ace $ace -TargetType $TargetType
            if ($null -ne $bh) { $list.Add($bh) }
        }
    } catch {}
    return $list
}

# ---------------------------------------------------------------------------
# Writer -- serialize one collection type to JSON
# ---------------------------------------------------------------------------
function Write-BHJson {
    param(
        [string]$Type,
        [object[]]$Data,
        [string]$Dir,
        [string]$Stamp
    )
    $dataArr = @($Data)
    $payload = [ordered]@{
        data = $dataArr
        meta = [ordered]@{
            methods = 0
            type    = $Type
            count   = $dataArr.Count
            version = 4
        }
    }
    $path = Join-Path $Dir ($Stamp + '_' + $Type + '.json')
    $json = $payload | ConvertTo-Json -Depth 20 -Compress
    [System.IO.File]::WriteAllText($path, $json, [System.Text.Encoding]::UTF8)
    Write-Verbose "  Wrote $path  ($($dataArr.Count) objects)"
    return $path
}

# ---------------------------------------------------------------------------
# Functional level integer -> readable string
# ---------------------------------------------------------------------------
$FL_LABELS = @{ 0='2000'; 1='2003 Interim'; 2='2003'; 3='2008'; 4='2008 R2'; 5='2012'; 6='2012 R2'; 7='2016' }

# ===========================================================================
# COLLECTION FUNCTIONS
# ===========================================================================

# ---------------------------------------------------------------------------
# DOMAIN
# ---------------------------------------------------------------------------
function Get-BHDomain {
    param([hashtable]$Dc, [string]$DomainSid)
    Write-Host '[*] Collecting domain ...' -ForegroundColor Cyan

    $ad = Get-LdapDomain @Dc
    $fl = if ($FL_LABELS.ContainsKey([int]$ad.DomainMode)) { $FL_LABELS[[int]$ad.DomainMode] } else { $ad.DomainMode.ToString() }

    $aces = Get-BHAces -DN $ad.DistinguishedName -TargetType 'Domain' -Dc $Dc

    # Trusts
    $trusts = [System.Collections.Generic.List[object]]::new()
    try {
        $tList = @(Find-LdapTrust -Filter * @Dc)
        foreach ($t in $tList) {
            $tDir = $t.Direction.ToString()
            $tSid = ''
            if ($t.SecurityIdentifier) { $tSid = $t.SecurityIdentifier.ToString() }
            $trusts.Add([ordered]@{
                TargetDomainSid     = $tSid
                TargetDomainName    = $t.Name.ToUpper()
                IsTransitive        = [bool]$t.IsTransitive
                TrustDirection      = $tDir
                TrustType           = $t.TrustType.ToString()
                SidFilteringEnabled = [bool]$t.SIDFilteringQuarantined
            })
        }
    } catch { Write-Warning "[Domain] Trust enum failed: $_" }

    # GPO links on the domain NC object
    $links = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($rawLink in @($ad.LinkedGroupPolicyObjects)) {
            foreach ($match in [regex]::Matches([string]$rawLink, '\[LDAP://[^\]]*\{([0-9A-Fa-f\-]+)\};(\d+)\]')) {
                $flag = [int]$match.Groups[2].Value
                $links.Add([ordered]@{
                    GUID       = $match.Groups[1].Value.ToUpper()
                    IsEnforced = (($flag -band 2) -ne 0)
                })
            }
        }
    } catch {}

    $node = [ordered]@{
        ObjectIdentifier = $DomainSid
        Properties       = [ordered]@{
            domain            = $ad.DNSRoot.ToUpper()
            name              = $ad.DNSRoot.ToUpper()
            distinguishedname = $ad.DistinguishedName.ToUpper()
            domainsid         = $DomainSid
            objectid          = $DomainSid
            highvalue         = $true
            description       = ''
            functionallevel   = $fl
            whencreated       = -1
        }
        Aces             = @($aces)
        Links            = @($links)
        ChildObjects     = @()
        Trusts           = @($trusts)
        IsDeleted        = $false
        IsACLProtected   = $false
    }
    return @($node)
}

# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------
function Get-BHUsers {
    param([hashtable]$Dc, [string]$DomainFQDN, [string]$DomainSid)
    Write-Host '[*] Collecting users ...' -ForegroundColor Cyan

    $props = @(
        'SamAccountName','UserPrincipalName','DistinguishedName','ObjectSID',
        'Enabled','AdminCount','Description','DisplayName','Title',
        'HomeDirectory','PasswordNeverExpires','PasswordNotRequired',
        'DoesNotRequirePreAuth','ServicePrincipalName','SIDHistory',
        'LastLogon','LastLogonTimeStamp','PasswordLastSet','WhenCreated',
        'TrustedForDelegation','TrustedToAuthForDelegation',
        'msDS-AllowedToDelegateTo','PrimaryGroupID','userAccountControl'
    )

    $list     = [System.Collections.Generic.List[object]]::new()
    $allUsers = @(Find-LdapUser -Filter * -Properties $props @Dc)
    Write-Verbose "  Found $($allUsers.Count) user accounts"

    foreach ($u in $allUsers) {
        $sid = $u.ObjectSID.ToString()
        Register-Sid $sid 'User'

        $aces   = Get-BHAces -DN $u.DistinguishedName -TargetType 'User' -Dc $Dc
        $spns   = @($u.ServicePrincipalName | Where-Object { $_ })
        $hasSPN = $spns.Count -gt 0

        # Constrained delegation targets
        $a2d = [System.Collections.Generic.List[object]]::new()
        $delegTo = $u.'msDS-AllowedToDelegateTo'
        if ($null -ne $delegTo) {
            foreach ($spn in @($delegTo)) {
                $a2d.Add([ordered]@{ ObjectIdentifier = $spn; ObjectType = 'Computer' })
            }
        }

        # SID history
        $sidHist = [System.Collections.Generic.List[string]]::new()
        if ($u.SIDHistory) {
            foreach ($sh in @($u.SIDHistory)) { $sidHist.Add($sh.ToString()) }
        }

        $lastLogonRaw   = if ($u.LastLogon)          { $u.LastLogon }          else { [int64]0 }
        $lastLogonTsRaw = if ($u.LastLogonTimeStamp) { $u.LastLogonTimeStamp } else { [int64]0 }
        $logon   = ConvertTo-Unix $lastLogonRaw
        $logonTs = ConvertTo-Unix $lastLogonTsRaw
        $pwdSet  = ConvertTo-Unix $u.PasswordLastSet
        $created = DateTo-Unix  $u.WhenCreated
        $pgSid   = "$DomainSid-$($u.PrimaryGroupID)"

        $uac            = if ($u.userAccountControl) { [int]$u.userAccountControl } else { 0 }
        $isSensitive    = ($uac -band 0x100000) -ne 0   # NOT_DELEGATED flag
        $isHighValue    = ($u.AdminCount -eq 1) -or ($sid -match '-500$|-502$')
        $displayName    = $u.SamAccountName.ToUpper() + '@' + $DomainFQDN.ToUpper()

        $node = [ordered]@{
            ObjectIdentifier  = $sid
            Properties        = [ordered]@{
                domain                = $DomainFQDN.ToUpper()
                name                  = $displayName
                distinguishedname     = $u.DistinguishedName.ToUpper()
                domainsid             = $DomainSid
                objectid              = $sid
                samaccountname        = $u.SamAccountName
                highvalue             = $isHighValue
                enabled               = [bool]$u.Enabled
                admincount            = ($u.AdminCount -eq 1)
                description           = if ($u.Description)    { [string]$u.Description }   else { '' }
                displayname           = if ($u.DisplayName)     { [string]$u.DisplayName }   else { '' }
                title                 = if ($u.Title)           { [string]$u.Title }          else { '' }
                homedirectory         = if ($u.HomeDirectory)   { [string]$u.HomeDirectory } else { '' }
                email                 = if ($u.UserPrincipalName) { [string]$u.UserPrincipalName } else { '' }
                dontreqpreauth        = [bool]$u.DoesNotRequirePreAuth
                passwordnotreqd       = [bool]$u.PasswordNotRequired
                sensitive             = $isSensitive
                pwdneverexpires       = [bool]$u.PasswordNeverExpires
                hasspn                = $hasSPN
                serviceprincipalnames = $spns
                unconstraineddelegation = [bool]$u.TrustedForDelegation
                trustedtoauth         = [bool]$u.TrustedToAuthForDelegation
                lastlogon             = $logon
                lastlogontimestamp    = $logonTs
                pwdlastset            = $pwdSet
                whencreated           = $created
                sidhistory            = @($sidHist)
                userpassword          = $null
            }
            Aces              = @($aces)
            SPNTargets        = @()
            AllowedToDelegate = @($a2d)
            PrimaryGroupSID   = $pgSid
            HasSIDHistory     = @($sidHist | ForEach-Object { [ordered]@{ ObjectIdentifier = $_; ObjectType = 'User' } })
            IsDeleted         = $false
            IsACLProtected    = $false
        }
        $list.Add($node)
    }
    return @($list)
}

# ---------------------------------------------------------------------------
# COMPUTERS
# ---------------------------------------------------------------------------
function Get-BHComputers {
    param([hashtable]$Dc, [string]$DomainFQDN, [string]$DomainSid)
    Write-Host '[*] Collecting computers ...' -ForegroundColor Cyan

    $props = @(
        'SamAccountName','DNSHostName','OperatingSystem','OperatingSystemVersion',
        'DistinguishedName','ObjectSID','Enabled','Description','AdminCount',
        'TrustedForDelegation','TrustedToAuthForDelegation',
        'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',
        'SIDHistory','LastLogon','LastLogonTimeStamp','PasswordLastSet',
        'WhenCreated','PrimaryGroupID','ServicePrincipalName',
        'ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime'
    )

    $list     = [System.Collections.Generic.List[object]]::new()
    $allComps = @(Find-LdapComputer -Filter * -Properties $props @Dc)
    Write-Verbose "  Found $($allComps.Count) computer accounts"

    $emptyCol = [ordered]@{ Results = @(); Collected = $false; FailureReason = $null }

    foreach ($c in $allComps) {
        $sid  = $c.ObjectSID.ToString()
        $isDC = ($c.PrimaryGroupID -eq 516 -or $c.PrimaryGroupID -eq 521)
        Register-Sid $sid 'Computer'

        $aces    = Get-BHAces -DN $c.DistinguishedName -TargetType 'Computer' -Dc $Dc
        # Use non-secret expiration attributes; never retrieve LAPS passwords.
        $hasLAPS = ($null -ne $c.'ms-Mcs-AdmPwdExpirationTime') -or
                   ($null -ne $c.'msLAPS-PasswordExpirationTime')

        # Constrained delegation
        $a2d = [System.Collections.Generic.List[object]]::new()
        $delegTo = $c.'msDS-AllowedToDelegateTo'
        if ($null -ne $delegTo) {
            foreach ($spn in @($delegTo)) {
                $a2d.Add([ordered]@{ ObjectIdentifier = $spn; ObjectType = 'Computer' })
            }
        }

        # RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
        $a2act   = [System.Collections.Generic.List[object]]::new()
        $rbcdRaw = $c.'msDS-AllowedToActOnBehalfOfOtherIdentity'
        if ($null -ne $rbcdRaw) {
            try {
                $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($rbcdRaw, 0)
                foreach ($ace in $sd.DiscretionaryAcl) {
                    $rbcdSid = $ace.SecurityIdentifier.ToString()
                    $a2act.Add([ordered]@{
                        ObjectIdentifier = $rbcdSid
                        ObjectType       = Get-SidType $rbcdSid
                    })
                }
            } catch {}
        }

        # SID history
        $sidHist = [System.Collections.Generic.List[string]]::new()
        if ($c.SIDHistory) {
            foreach ($sh in @($c.SIDHistory)) { $sidHist.Add($sh.ToString()) }
        }

        $lastLogonRaw   = if ($c.LastLogon)          { $c.LastLogon }          else { [int64]0 }
        $lastLogonTsRaw = if ($c.LastLogonTimeStamp) { $c.LastLogonTimeStamp } else { [int64]0 }
        $logon   = ConvertTo-Unix $lastLogonRaw
        $logonTs = ConvertTo-Unix $lastLogonTsRaw
        $pwdSet  = ConvertTo-Unix $c.PasswordLastSet
        $created = DateTo-Unix  $c.WhenCreated
        $pgSid   = "$DomainSid-$($c.PrimaryGroupID)"

        $dnsName    = if ($c.DNSHostName) { $c.DNSHostName.ToUpper() } else { $c.SamAccountName.TrimEnd('$').ToUpper() + '.' + $DomainFQDN.ToUpper() }
        $isHighValue = $isDC -or ($c.AdminCount -eq 1)

        $node = [ordered]@{
            ObjectIdentifier   = $sid
            Properties         = [ordered]@{
                domain                  = $DomainFQDN.ToUpper()
                name                    = $dnsName
                distinguishedname       = $c.DistinguishedName.ToUpper()
                domainsid               = $DomainSid
                objectid                = $sid
                samaccountname          = $c.SamAccountName
                highvalue               = $isHighValue
                enabled                 = [bool]$c.Enabled
                operatingsystem         = if ($c.OperatingSystem)        { [string]$c.OperatingSystem }        else { '' }
                operatingsystemversion  = if ($c.OperatingSystemVersion) { [string]$c.OperatingSystemVersion } else { '' }
                description             = if ($c.Description)            { [string]$c.Description }            else { '' }
                admincount              = ($c.AdminCount -eq 1)
                unconstraineddelegation = [bool]$c.TrustedForDelegation
                trustedtoauth           = [bool]$c.TrustedToAuthForDelegation
                haslaps                 = $hasLAPS
                lastlogon               = $logon
                lastlogontimestamp      = $logonTs
                pwdlastset              = $pwdSet
                whencreated             = $created
                serviceprincipalnames   = @($c.ServicePrincipalName | Where-Object { $_ })
                sidhistory              = @($sidHist)
            }
            PrimaryGroupSID    = $pgSid
            AllowedToDelegate  = @($a2d)
            AllowedToAct       = @($a2act)
            HasSIDHistory      = @($sidHist | ForEach-Object { [ordered]@{ ObjectIdentifier = $_; ObjectType = 'Computer' } })
            Sessions           = $emptyCol
            PrivilegedSessions = $emptyCol
            RegistrySessions   = $emptyCol
            LocalAdmins        = $emptyCol
            RemoteDesktopUsers = $emptyCol
            DcomUsers          = $emptyCol
            PSRemoteUsers      = $emptyCol
            Aces               = @($aces)
            IsDeleted          = $false
            IsACLProtected     = $false
            IsDC               = $isDC
            DumpSMBInfo        = $false
        }
        $list.Add($node)
    }
    return @($list)
}

# ---------------------------------------------------------------------------
# GROUPS
# ---------------------------------------------------------------------------
function Get-BHGroups {
    param([hashtable]$Dc, [string]$DomainFQDN, [string]$DomainSid)
    Write-Host '[*] Collecting groups ...' -ForegroundColor Cyan

    $props    = @('SamAccountName','DistinguishedName','ObjectSID','Description',
                  'AdminCount','WhenCreated','Members','GroupScope','GroupCategory')
    $list     = [System.Collections.Generic.List[object]]::new()
    $allGroups = @(Find-LdapGroup -Filter * -Properties $props @Dc)
    Write-Verbose "  Found $($allGroups.Count) groups"

    # High-value RIDs (domain + BUILTIN)
    $hvRids = @(512,516,518,519,520,544,548,549,550,551,552)

    foreach ($g in $allGroups) {
        $sid = $g.ObjectSID.ToString()
        Register-Sid $sid 'Group'

        $ridPart = ($sid -split '-')[-1]
        $rid     = 0
        $ridIsHV = [int]::TryParse($ridPart, [ref]$rid) -and ($hvRids -contains $rid)
        $isHighValue = $ridIsHV -or ($g.AdminCount -eq 1)

        $aces = Get-BHAces -DN $g.DistinguishedName -TargetType 'Group' -Dc $Dc

        # Members -- resolve each DN to SID + type
        $members = [System.Collections.Generic.List[object]]::new()
        $rawMembers = @($g.Members)
        foreach ($mDn in $rawMembers) {
            try {
                $mObj = Get-LdapObject -Identity $mDn -Properties ObjectSID,objectClass @Dc
                if ($null -ne $mObj -and $null -ne $mObj.ObjectSID) {
                    $mSid  = $mObj.ObjectSID.ToString()
                    $mType = switch ($mObj.objectClass[-1]) {
                        'user'     { 'User' }
                        'computer' { 'Computer' }
                        'group'    { 'Group' }
                        default    { 'Unknown' }
                    }
                    Register-Sid $mSid $mType
                    $members.Add([ordered]@{ ObjectIdentifier = $mSid; ObjectType = $mType })
                }
            } catch {}
        }

        $created = DateTo-Unix $g.WhenCreated

        $node = [ordered]@{
            ObjectIdentifier = $sid
            Properties       = [ordered]@{
                domain            = $DomainFQDN.ToUpper()
                name              = ($g.SamAccountName.ToUpper() + '@' + $DomainFQDN.ToUpper())
                distinguishedname = $g.DistinguishedName.ToUpper()
                domainsid         = $DomainSid
                objectid          = $sid
                samaccountname    = $g.SamAccountName
                highvalue         = $isHighValue
                admincount        = ($g.AdminCount -eq 1)
                description       = if ($g.Description) { [string]$g.Description } else { '' }
                whencreated       = $created
            }
            Members          = @($members)
            Aces             = @($aces)
            IsDeleted        = $false
            IsACLProtected   = $false
        }
        $list.Add($node)
    }
    return @($list)
}

# ---------------------------------------------------------------------------
# GPOs
# ---------------------------------------------------------------------------
function Get-BHGPOs {
    param([hashtable]$Dc, [string]$DomainFQDN, [string]$DomainSid)
    Write-Host '[*] Collecting GPOs ...' -ForegroundColor Cyan

    $list = [System.Collections.Generic.List[object]]::new()

    try {
        $adDomain = Get-LdapDomain @Dc
        $allGPOs  = @(Find-LdapGPO -All @Dc)
        foreach ($gpo in $allGPOs) {
            $gpoGuid = $gpo.Id.ToString().ToUpper()
            $gpoDN   = "CN={$gpoGuid},CN=Policies,CN=System,$($adDomain.DistinguishedName)"
            $aces    = Get-BHAces -DN $gpoDN -TargetType 'GPO' -Dc $Dc
            $created = DateTo-Unix $gpo.CreationTime
            $desc    = if ($gpo.Description) { [string]$gpo.Description } else { '' }

            $node = [ordered]@{
                ObjectIdentifier = $gpoGuid
                Properties       = [ordered]@{
                    domain            = $DomainFQDN.ToUpper()
                    name              = ($gpo.DisplayName.ToUpper() + '@' + $DomainFQDN.ToUpper())
                    distinguishedname = $gpoDN.ToUpper()
                    domainsid         = $DomainSid
                    objectid          = $gpoGuid
                    highvalue         = $false
                    description       = $desc
                    whencreated       = $created
                    gpcpath           = "\\$DomainFQDN\SYSVOL\$DomainFQDN\Policies\{$gpoGuid}"
                }
                Aces             = @($aces)
                IsDeleted        = $false
                IsACLProtected   = $false
            }
            $list.Add($node)
        }
    } catch { Write-Warning "[GPO] Collection failed: $_" }
    return @($list)
}

# ---------------------------------------------------------------------------
# OUs
# ---------------------------------------------------------------------------
function Get-BHOUs {
    param([hashtable]$Dc, [string]$DomainFQDN, [string]$DomainSid)
    Write-Host '[*] Collecting OUs ...' -ForegroundColor Cyan

    $props  = @('DistinguishedName','Name','Description','WhenCreated',
                'gpLink','gPOptions','ObjectGUID')
    $list   = [System.Collections.Generic.List[object]]::new()
    $allOUs = @(Find-LdapOrganizationalUnit -Filter * -Properties $props @Dc)
    Write-Verbose "  Found $($allOUs.Count) OUs"

    foreach ($ou in $allOUs) {
        $ouGuid = $ou.ObjectGUID.ToString().ToUpper()
        $aces   = Get-BHAces -DN $ou.DistinguishedName -TargetType 'OU' -Dc $Dc

        # GPO links on this OU
        $links = [System.Collections.Generic.List[object]]::new()
        if ($ou.gpLink) {
            $lmatch = [regex]::Matches($ou.gpLink, '\{([0-9A-Fa-f\-]+)\}(?:;(\d))?')
            foreach ($m in $lmatch) {
                $flag = $m.Groups[2].Value
                $links.Add([ordered]@{
                    GUID       = $m.Groups[1].Value.ToUpper()
                    IsEnforced = ($flag -eq '2' -or $flag -eq '3')
                })
            }
        }

        $blocksInherit = ($ou.gPOptions -band 1) -ne 0
        $created       = DateTo-Unix $ou.WhenCreated
        $desc          = if ($ou.Description) { [string]$ou.Description } else { '' }

        $node = [ordered]@{
            ObjectIdentifier = $ouGuid
            Properties       = [ordered]@{
                domain            = $DomainFQDN.ToUpper()
                name              = ($ou.Name.ToUpper() + '@' + $DomainFQDN.ToUpper())
                distinguishedname = $ou.DistinguishedName.ToUpper()
                domainsid         = $DomainSid
                objectid          = $ouGuid
                highvalue         = $false
                description       = $desc
                whencreated       = $created
                blocksinheritance = $blocksInherit
            }
            Aces             = @($aces)
            Links            = @($links)
            ChildObjects     = @()
            IsDeleted        = $false
            IsACLProtected   = $false
        }
        $list.Add($node)
    }
    return @($list)
}

# ===========================================================================
# MAIN
# ===========================================================================
Write-Host ''
Write-Host '=== AD Attack-Path Collector (PS5.1 native) ===' -ForegroundColor Magenta
$dcDisplay = if ($DomainController) { $DomainController } else { '(auto-discover)' }
Write-Host ("    Target DC : " + $dcDisplay) -ForegroundColor Gray
Write-Host ''

# Resolve and create output directory
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if (-not (Test-Path -LiteralPath $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    } catch {
        $fallback = Join-Path $env:TEMP 'BHCollect'
        Write-Warning "Cannot create $OutputPath -- falling back to $fallback"
        $OutputPath = $fallback
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
}
Write-Host "    Output    : $OutputPath" -ForegroundColor Gray
Write-Host ''

$dcParam = Get-DcParam

# Resolve domain info
Write-Host '[*] Resolving domain ...' -ForegroundColor Cyan
Initialize-LdapContext
$adDomain  = Get-LdapDomain @dcParam
$domFQDN   = $adDomain.DNSRoot
$domSid    = $adDomain.DomainSID.ToString()
Write-Verbose "  Domain : $domFQDN"
Write-Verbose "  SID    : $domSid"

# Resolve LAPS attribute GUID
$script:LAPSGuid = @(Get-LAPSGuid -Dc $dcParam)
if ($script:LAPSGuid.Count -gt 0) {
    Write-Verbose "  LAPS attribute GUIDs : $($script:LAPSGuid -join ', ')"
} else {
    Write-Verbose '  Legacy/Windows LAPS password attributes not found in schema'
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
$files = [System.Collections.Generic.List[string]]::new()

# NOTE: group and computer collections are done BEFORE users so the SidMap
# is partially populated before Convert-Ace tries to resolve principal types
# for user-object ACEs.

$groupData    = @(Get-BHGroups    -Dc $dcParam -DomainFQDN $domFQDN -DomainSid $domSid)
$computerData = @(Get-BHComputers -Dc $dcParam -DomainFQDN $domFQDN -DomainSid $domSid)
$userData     = @(Get-BHUsers     -Dc $dcParam -DomainFQDN $domFQDN -DomainSid $domSid)
$domainData   = @(Get-BHDomain    -Dc $dcParam -DomainSid  $domSid)
$gpoData      = @(Get-BHGPOs      -Dc $dcParam -DomainFQDN $domFQDN -DomainSid $domSid)
$ouData       = @(Get-BHOUs       -Dc $dcParam -DomainFQDN $domFQDN -DomainSid $domSid)

Write-Host ''
Write-Host '[*] Writing JSON files ...' -ForegroundColor Cyan

$files.Add((Write-BHJson -Type 'groups'    -Data $groupData    -Dir $OutputPath -Stamp $stamp))
$files.Add((Write-BHJson -Type 'computers' -Data $computerData -Dir $OutputPath -Stamp $stamp))
$files.Add((Write-BHJson -Type 'users'     -Data $userData     -Dir $OutputPath -Stamp $stamp))
$files.Add((Write-BHJson -Type 'domains'   -Data $domainData   -Dir $OutputPath -Stamp $stamp))
$files.Add((Write-BHJson -Type 'gpos'      -Data $gpoData      -Dir $OutputPath -Stamp $stamp))
$files.Add((Write-BHJson -Type 'ous'       -Data $ouData       -Dir $OutputPath -Stamp $stamp))

# Zip all JSON files for BloodHound "Upload Data" ingest
if (-not $NoCompress) {
    $zipPath = Join-Path $OutputPath ($stamp + '_ADCollection.zip')
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
        foreach ($f in $files) {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip,
                $f,
                [System.IO.Path]::GetFileName($f),
                [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        }
        $zip.Dispose()
        Write-Host ''
        Write-Host "[+] ZIP : $zipPath" -ForegroundColor Green
        Write-Host "    Drag-and-drop into BloodHound 'Upload Data' to ingest." -ForegroundColor Gray
    } catch {
        Write-Warning "ZIP creation failed: $_ -- JSON files are still usable."
    }
}

Write-Host ''
Write-Host '[+] Collection complete.' -ForegroundColor Green
Write-Host ''
Write-Host 'Summary:' -ForegroundColor Yellow
Write-Host ("  Domains   : " + $domainData.Count)   -ForegroundColor Gray
Write-Host ("  Users     : " + $userData.Count)      -ForegroundColor Gray
Write-Host ("  Computers : " + $computerData.Count)  -ForegroundColor Gray
Write-Host ("  Groups    : " + $groupData.Count)     -ForegroundColor Gray
Write-Host ("  GPOs      : " + $gpoData.Count)       -ForegroundColor Gray
Write-Host ("  OUs       : " + $ouData.Count)        -ForegroundColor Gray
Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Yellow
Write-Host "  1. Import the ZIP into BloodHound via 'Upload Data'" -ForegroundColor Gray
Write-Host "  2. Run PlumHound against Neo4j:" -ForegroundColor Gray
Write-Host "       python3 PlumHound.py -x tasks/default.tasks -p <neo4j-password>" -ForegroundColor Gray
Write-Host "  3. Open PlumHound HTML reports in reports/" -ForegroundColor Gray
Write-Host ''
