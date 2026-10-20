param([string]$Path = 'D:\Code\chusan_reverse\SDHD\bin\chusanApp.exe')

$ErrorActionPreference = 'Stop'
$bytes = [System.IO.File]::ReadAllBytes($Path)
$peOff = [int][System.BitConverter]::ToInt32($bytes, 0x3C)
$imageBase = [int64][System.BitConverter]::ToUInt32($bytes, $peOff + 0x34)
$numSec = [int][System.BitConverter]::ToUInt16($bytes, $peOff + 6)
$optSize = [int][System.BitConverter]::ToUInt16($bytes, $peOff + 20)
$secOff = $peOff + 24 + $optSize

$sections = @()
for ($i = 0; $i -lt $numSec; $i++) {
    $o = $secOff + $i * 40
    $sections += [pscustomobject]@{
        Name = [System.Text.Encoding]::ASCII.GetString($bytes, $o, 8).Trim([char]0)
        VS   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 8)
        VA   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 12)
        PR   = [int64][System.BitConverter]::ToUInt32($bytes, $o + 20)
    }
}

function Get-SectionName([int64]$rva) {
    foreach ($s in $sections) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VS)) { return $s.Name }
    }
    return '<none>'
}
function Get-Offset([int64]$va) {
    $rva = $va - $imageBase
    foreach ($s in $sections) {
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VS)) { return [int64]($rva - $s.VA + $s.PR) }
    }
    return [int64](-1)
}
function HexAt([int64]$va, [int]$n) {
    $o = Get-Offset $va
    if ($o -lt 0) { return '<unmapped>' }
    return (($bytes[$o..($o + $n - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' ')
}
function U32At([int64]$va) {
    $o = Get-Offset $va
    if ($o -lt 0) { return [int64](-1) }
    return [int64][System.BitConverter]::ToUInt32($bytes, $o)
}

$L = [Console]::WriteLine

$L.Invoke("ImageBase = 0x" + $imageBase.ToString('X'))
$L.Invoke("")

# --- Data directories -------------------------------------------------------
$dirNames = @('Export','Import','Resource','Exception','Certificate','BaseReloc',
              'Debug','Architecture','GlobalPtr','TLS','LoadConfig','BoundImport',
              'IAT','DelayImport','CLR','Reserved')
$L.Invoke("=== data directories (RVA / size) ===")
for ($i = 0; $i -lt 16; $i++) {
    $d = $peOff + 24 + 96 + $i * 8
    $rva = [System.BitConverter]::ToUInt32($bytes, $d)
    $sz = [System.BitConverter]::ToUInt32($bytes, $d + 4)
    if ($rva -ne 0) {
        $L.Invoke(("  {0,-12} RVA=0x{1:X8} size=0x{2:X} [{3}]" -f $dirNames[$i], $rva, $sz, (Get-SectionName $rva)))
    }
}
$L.Invoke("")

# --- Delay import descriptors ----------------------------------------------
$diRva = [int64][System.BitConverter]::ToUInt32($bytes, $peOff + 24 + 96 + 13 * 8)
$L.Invoke("=== delay-load imports ===")
if ($diRva -eq 0) {
    $L.Invoke("  none (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT is empty)")
} else {
    $o = Get-Offset ($imageBase + $diRva)
    while ($true) {
        $attrs = [System.BitConverter]::ToUInt32($bytes, $o)
        $nameRva = [System.BitConverter]::ToUInt32($bytes, $o + 4)
        $modRva = [System.BitConverter]::ToUInt32($bytes, $o + 8)
        if ($nameRva -eq 0 -and $modRva -eq 0) { break }
        $no = Get-Offset ($imageBase + $nameRva)
        $nm = ''
        if ($no -ge 0) { $e = $no; while ($bytes[$e] -ne 0) { $nm += [char]$bytes[$e]; $e++ } }
        $L.Invoke("  " + $nm + "  attrs=0x" + $attrs.ToString('X'))
        $o += 32
    }
}
$L.Invoke("")

# --- ws2_32 import descriptor + IAT slot enumeration ------------------------
$impRva = [int64][System.BitConverter]::ToUInt32($bytes, $peOff + 24 + 96 + 1 * 8)
$desc = Get-Offset ($imageBase + $impRva)
$L.Invoke("=== ws2_32 import: IAT slot addresses (ordinal order as in file) ===")
$slotIndex = 0
while ($true) {
    $oft = [System.BitConverter]::ToUInt32($bytes, $desc)
    $ft = [System.BitConverter]::ToUInt32($bytes, $desc + 16)
    $nameRva2 = [System.BitConverter]::ToUInt32($bytes, $desc + 12)
    if ($nameRva2 -eq 0) { break }
    $no = Get-Offset ($imageBase + $nameRva2)
    $dll = ''
    if ($no -ge 0) { $e = $no; while ($bytes[$e] -ne 0) { $dll += [char]$bytes[$e]; $e++ } }

    if ($dll -ieq 'WS2_32.dll' -or $dll -ieq 'ws2_32.dll') {
        $L.Invoke("  dll=" + $dll + "  IAT VA=0x" + ($imageBase + $ft).ToString('X') + "  INT VA=0x" + ($imageBase + $oft).ToString('X'))
        $intOff = Get-Offset ($imageBase + $oft)
        $k = 0
        while ($true) {
            $thunk = [System.BitConverter]::ToUInt32($bytes, $intOff + $k * 4)
            if ($thunk -eq 0) { break }
            $slotVa = $imageBase + $ft + $k * 4
            $label = ''
            if (($thunk -band 0x80000000) -ne 0) {
                $label = 'Ordinal ' + ($thunk -band 0xFFFF)
            } else {
                $nb = Get-Offset ($imageBase + $thunk)
                if ($nb -ge 0) { $e = $nb + 2; while ($bytes[$e] -ne 0) { $label += [char]$bytes[$e]; $e++ } }
            }
            $mark = ''
            if ($label -eq 'Ordinal 2') { $mark = '   <== bind' }
            $L.Invoke(("    idx={0,-3} slot=0x{1:X8}  {2}{3}" -f $k, $slotVa, $label, $mark))
            $k++
        }
    }
    $desc += 20
}
$L.Invoke("")

# --- Follow the bind call chain --------------------------------------------
$L.Invoke("=== bind call site 0xA560A1 and its thunk chain ===")
$va = [int64]0xA560A1
for ($step = 0; $step -lt 6; $step++) {
    $op = $bytes[(Get-Offset $va)]
    if ($op -eq 0xE8 -or $op -eq 0xE9) {
        $rel = [System.BitConverter]::ToInt32($bytes, (Get-Offset $va) + 1)
        $tgt = $va + 5 + $rel
        $kind = if ($op -eq 0xE8) { 'call' } else { 'jmp ' }
        $L.Invoke(("  0x{0:X8}: {1} 0x{2:X8}   [{3}]" -f $va, $kind, $tgt, (Get-SectionName ($va - $imageBase))))
        $va = $tgt
        continue
    }
    if ($op -eq 0xFF) {
        $modrm = $bytes[(Get-Offset $va) + 1]
        if ($modrm -eq 0x25 -or $modrm -eq 0x15) {
            $slot = [int64][System.BitConverter]::ToUInt32($bytes, (Get-Offset $va) + 2)
            $kind = if ($modrm -eq 0x25) { 'jmp ' } else { 'call' }
            $rva = $slot - $imageBase
            $L.Invoke(("  0x{0:X8}: {1} dword ptr [0x{2:X8}]   slot is in [{3}]" -f $va, $kind, $slot, (Get-SectionName $rva)))
            $L.Invoke("           -> IAT slot VA 0x" + $slot.ToString('X') + "  (ordinal 2 / bind slot = 0x221AC14)")
            break
        }
    }
    $L.Invoke(("  0x{0:X8}: {1}   [{2}]  (chain ends)" -f $va, (HexAt $va 8), (Get-SectionName ($va - $imageBase))))
    break
}
