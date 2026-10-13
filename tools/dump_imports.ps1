param([Parameter(Mandatory=$true)][string]$Path)
$b=[IO.File]::ReadAllBytes($Path)
$peOff=[BitConverter]::ToInt32($b,0x3C)
$machine=[BitConverter]::ToUInt16($b,$peOff+4)
$nsec=[BitConverter]::ToUInt16($b,$peOff+6)
$optSize=[BitConverter]::ToUInt16($b,$peOff+20)
$optOff=$peOff+24
$magic=[BitConverter]::ToUInt16($b,$optOff)
$imgBase=[BitConverter]::ToUInt32($b,$optOff+28)
$ddOff = if ($magic -eq 0x10b) { $optOff+96 } else { $optOff+112 }
$importRva=[BitConverter]::ToUInt32($b,$ddOff+8)
$secOff=$optOff+$optSize
$secs=@()
for($i=0;$i -lt $nsec;$i++){
  $o=$secOff+40*$i
  $secs += [pscustomobject]@{
    VA=[BitConverter]::ToUInt32($b,$o+12)
    VS=[BitConverter]::ToUInt32($b,$o+8)
    Raw=[BitConverter]::ToUInt32($b,$o+20)
  }
}
function R2O($rva){
  foreach($s in $secs){
    $span=[Math]::Max($s.VS,$s.Raw)
    if($rva -ge $s.VA -and $rva -lt ($s.VA + $span)){ return [int]($s.Raw + ($rva - $s.VA)) }
  }
  return -1
}
Write-Output ("FILE={0}" -f (Split-Path $Path -Leaf))
Write-Output ("SIZE={0} MACHINE=0x{1:X} IMAGEBASE=0x{2:X}" -f $b.Length,$machine,$imgBase)
$all=@()
if($importRva -ne 0){
  $off=R2O $importRva
  while($off -gt 0){
    $ilt=[BitConverter]::ToUInt32($b,$off)
    $nameRva=[BitConverter]::ToUInt32($b,$off+12)
    if($ilt -eq 0 -and $nameRva -eq 0){break}
    $nOff=R2O $nameRva
    $end=$nOff
    while($b[$end] -ne 0){$end++}
    $dll=[Text.Encoding]::ASCII.GetString($b,$nOff,$end-$nOff)
    $tOff=R2O $ilt
    while($true){
      $v=[BitConverter]::ToUInt32($b,$tOff)
      if($v -eq 0){break}
      if(($v -band 0x80000000) -ne 0){
        $all += ("{0}!ord{1}" -f $dll,($v -band 0xFFFF))
      } else {
        $hOff=R2O $v
        $e=$hOff+2
        while($b[$e] -ne 0){$e++}
        $all += ("{0}!{1}" -f $dll,[Text.Encoding]::ASCII.GetString($b,$hOff+2,$e-$hOff-2))
      }
      $tOff+=4
    }
    $off+=20
  }
}
Write-Output ("IMPORTS=" + $all.Count)
$all | Sort-Object | ForEach-Object { Write-Output ("  " + $_) }