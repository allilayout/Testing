[void][Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')

$AmsiAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -like "*Management.Automation*" }
$TargetType = $AmsiAssembly.GetTypes() | Where-Object { $_.Name -like "*Amsi*Utils*" }

$Methods = $TargetType.GetMethods([Reflection.BindingFlags]"Static,NonPublic")

if ($null -eq $Methods) { 
    Write-Error "Discovery Failed: Check if you are in a 32-bit PowerShell 5.1 session." 
} else {
    Write-Host "Success: helo0 discovered $($Methods.Count) internal methods." -ForegroundColor Green
}
