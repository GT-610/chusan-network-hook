param(
    [string]$Path = 'D:\Code\chusan_reverse\SDHD\bin\chusanApp.exe',
    [string]$Slot = '0x0221AC14'   # ws2_32 ordinal 2 = bind, from the IAT table
)

$ErrorActionPreference = 'Stop'
$bytes = [System.IO.File]::ReadAllBytes($Path)
$peOff = [int][System.BitConverter]::ToInt32($bytes, 0x3C)
$imageBase = [int64][System.BitConverter]::ToUInt32($bytes, $peOff + 0x34)
$numSec = [int][System.BitConverter]::ToUInt16($bytes, $peOff + 6)
$optSize = [int][System.BitConverter]::ToUInt16($bytes, $peOff + 20)
$secOff = $peOff + 24 + $optSize
$target = [int64][System.Convert]::ToInt64($Slot, 16)

# The whole address space is 32-bit; every absolute reference is 4 bytes.
$needle = [System.BitConverter]::GetBytes([uint32]$target)

# Build a RVA<->file-offset map and remember which ranges are executable.
$sections = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secOff + $i * 40
    $sections += [pscustomobject]@{
        Name = [System.Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0)
        VS   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 8)
        VA   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 12)
        RS   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 16)
        PR   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 20)
        Flags = [int64][System.BitConverter]::ToUInt32($bytes, $o + 36)
    }
}
function OffToVa([int64]$off) {
    foreach ($s in $sections) {
        if ($off -ge $s.PR -and $off -lt ($s.PR + $s.RS)) { return [int64]($off - $s.PR + $s.VA + $imageBase) }
    }
    return [int64](-1)
}
function NameOfVa([int64]$va) {
    $rva = $va - $imageBase
    foreach ($s in $sections) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VS)) { return $s.Name }
    }
    return '<none>'
}

[Console]::WriteLine("Scanning $Path for absolute references to 0x" + $target.ToString('X8'))
[Console]::WriteLine("")

$hits = @()
for ($i = 0; $i -lt ($bytes.Length - 4); $i++) {
    if ($bytes[$i] -ne $needle[0]) { continue }
    if ($bytes[$i + 1] -ne $needle[1]) { continue }
    if ($bytes[$i + 2] -ne $needle[2]) { continue }
    if ($bytes[$i + 3] -ne $needle[3]) { continue }

    $va = OffToVa $i
    if ($va -lt 0) { continue }

    # Classify by the two preceding bytes (x86 modrm forms for [disp32]).
    $kind = 'data/other'
    if ($i -ge 2) {
        $p1 = $bytes[$i - 2]; $p2 = $bytes[$i - 1]
        if ($p1 -eq 0xFF -and $p2 -eq 0x15) { $kind = 'call dword ptr' }
        elseif ($p1 -eq 0xFF -and $p2 -eq 0x25) { $kind = 'jmp  dword ptr' }
    }
    $hits += [pscustomobject]@{ VA = $va; Kind = $kind; Sec = (NameOfVa $va) }
}

$L = [Console]::WriteLine
$L.Invoke("total references to the bind slot: " + $hits.Count)
$L.Invoke("")
foreach ($h in $hits) {
    $L.Invoke(("  0x{0:X8}  {1,-16} [{2}]" -f $h.VA, $h.Kind, $h.Sec))
}

# Repeat for socket (ordinal 23) as a control, so "no hits" cannot be blamed on the scan.
$L.Invoke("")
$L.Invoke("=== control: references to the socket slot 0x0221AC48 (ordinal 23) ===")
$needle2 = [System.BitConverter]::GetBytes([uint32]0x0221AC48)
$n2 = 0
for ($i = 0; $i -lt ($bytes.Length - 4); $i++) {
    if ($bytes[$i] -ne $needle2[0]) { continue }
    if ($bytes[$i + 1] -ne $needle2[1]) { continue }
    if ($bytes[$i + 2] -ne $needle2[2]) { continue }
    if ($bytes[$i + 3] -ne $needle2[3]) { continue }
    $va = OffToVa $i
    if ($va -lt 0) { continue }
    $kind = 'data/other'
    if ($i -ge 2) {
        $p1 = $bytes[$i - 2]; $p2 = $bytes[$i - 1]
        if ($p1 -eq 0xFF -and $p2 -eq 0x15) { $kind = 'call dword ptr' }
        elseif ($p1 -eq 0xFF -and $p2 -eq 0x25) { $kind = 'jmp  dword ptr' }
    }
    $L.Invoke(("  0x{0:X8}  {1,-16} [{2}]" -f $va, $kind, (NameOfVa $va)))
    $n2++
}
$L.Invoke("socket slot references: " + $n2)
