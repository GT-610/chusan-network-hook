param([Parameter(Mandatory=$true)][string]$Path)
$b=[IO.File]::ReadAllBytes($Path)

# Locate the "Rich" signature, then the XOR key that follows it.
$rich=-1
for($i=0;$i -lt $b.Length-4;$i++){
  if($b[$i] -eq 0x52 -and $b[$i+1] -eq 0x69 -and $b[$i+2] -eq 0x63 -and $b[$i+3] -eq 0x68){ $rich=$i; break }
}
if($rich -lt 0){ Write-Output "NO RICH HEADER"; exit 0 }
$key=[BitConverter]::ToUInt32($b,$rich+4)

# The DanS signature sits at a fixed offset (0x80) for PE images.
$dansOff=0x80
if($dansOff -gt $rich){ Write-Output "BAD OFFSETS"; exit 0 }

function X([uint32]$v){ return ($v -bxor $key) }
$sig=X ([BitConverter]::ToUInt32($b,$dansOff))
if($sig -ne 0x536E6144){ Write-Output ("DANS MISMATCH: 0x{0:X8}" -f $sig); exit 0 }

Write-Output ("RICH_HEADER_FOUND key=0x{0:X8} span={1}" -f $key, ($rich-$dansOff))
# Entries begin after the 16-byte DanS+padding header, each (compid, count) pair.
$entries=@()
for($o=$dansOff+16; $o -lt $rich; $o+=8){
  $compid = X ([BitConverter]::ToUInt32($b,$o))
  $count  = X ([BitConverter]::ToUInt32($b,$o+4))
  $prodId = ($compid -shr 16) -band 0xFFFF
  $build  = $compid -band 0xFFFF
  $entries += [pscustomobject]@{ProdId=$prodId;Build=$build;Count=$count}
}
Write-Output "COMPID  BUILD    COUNT  DESCRIPTION"
foreach($e in $entries){
  $desc = switch ($e.ProdId) {
    1 {"Import0 (imports, old toolset)"}
    2 {"Linker510"}
    3 {"Cvtomf510"}
    4 {"Linker600"}
    5 {"Cvtomf600"}
    6 {"Cvtres500"}
    7 {"Utc11_Basic"}
    8 {"Utc11_C"}
    9 {"Utc12_Basic"}
    10 {"Utc12_C"}
    11 {"Utc12_CPP"}
    12 {"AliasObj60"}
    13 {"VisualBasic60"}
    14 {"Masm613"}
    15 {"Masm710"}
    16 {"Linker511"}
    17 {"Cvtomf511"}
    18 {"Masm614"}
    19 {"Linker512"}
    20 {"Cvtomf512"}
    21 {"Utc12_C_Std"}
    22 {"Utc12_CPP_Std"}
    23 {"Utc12_C_Book"}
    24 {"Utc12_CPP_Book"}
    25 {"Implib700"}
    26 {"Cvtomf700"}
    27 {"Utc13_Basic"}
    28 {"Utc13_C"}
    29 {"Utc13_CPP"}
    30 {"Linker610"}
    31 {"Cvtomf610"}
    32 {"Linker601"}
    33 {"Cvtomf601"}
    34 {"Utc12_1_Basic"}
    35 {"Utc12_1_C"}
    36 {"Utc12_1_CPP"}
    37 {"Linker620"}
    38 {"Cvtomf620"}
    39 {"AliasObj620"}
    40 {"Linker621"}
    41 {"Cvtomf621"}
    42 {"Masm615"}
    43 {"Utc13_LTCG_C"}
    44 {"Utc13_LTCG_CPP"}
    45 {"Masm620"}
    46 {"ILAsm100"}
    47 {"Utc12_2_Basic"}
    48 {"Utc12_2_C"}
    49 {"Utc12_2_CPP"}
    50 {"Utc12_2_C_Std"}
    51 {"Utc12_2_CPP_Std"}
    52 {"Utc12_2_C_Book"}
    53 {"Utc12_2_CPP_Book"}
    54 {"Implib622"}
    55 {"Cvtomf622"}
    56 {"Cvtres501"}
    57 {"Utc13_C_Std"}
    58 {"Utc13_CPP_Std"}
    59 {"Cvtres700"}
    60 {"Masm700"}
    61 {"Implib700"}
    62 {"Linker621"}
    83 {"Linker710"}
    84 {"Cvtomf710"}
    85 {"Utc14_Basic"}
    86 {"Utc14_C"}
    87 {"Utc14_CPP"}
    93 {"Linker800"}
    94 {"Cvtomf800"}
    95 {"Utc15_Basic"}
    96 {"Utc15_C"}
    97 {"Utc15_CPP"}
    102 {"Linker900"}
    103 {"Cvtres900"}
    104 {"Masm900"}
    105 {"Utc16_C"}
    106 {"Utc16_CPP"}
    107 {"Linker1000"}
    108 {"Cvtres1000"}
    109 {"Export1000"}
    110 {"Implib1000"}
    111 {"Linker1010"}
    112 {"Cvtres1010"}
    113 {"Export1010"}
    114 {"Implib1010"}
    118 {"Linker1100"}
    119 {"Cvtres1100"}
    120 {"Export1100"}
    121 {"Implib1100"}
    128 {"Utc1700_C"}
    129 {"Utc1700_CPP"}
    130 {"Linker1200"}
    131 {"Cvtres1200"}
    132 {"Export1200"}
    133 {"Implib1200"}
    135 {"Utc1800_C"}
    136 {"Utc1800_CPP"}
    137 {"Linker1300"}
    138 {"Cvtres1300"}
    139 {"Export1300"}
    140 {"Implib1300"}
    147 {"Utc1900_C"}
    148 {"Utc1900_CPP"}
    149 {"Linker1400"}
    150 {"Cvtres1400"}
    151 {"Export1400"}
    152 {"Implib1400"}
    158 {"Linker1500"}
    159 {"Cvtres1500"}
    170 {"Utc1910_C"}
    171 {"Utc1910_CPP"}
    172 {"Linker1600"}
    173 {"Cvtres1600"}
    175 {"Implib1700"}
    default {"(unmapped)"}
  }
  "  0x{0:X2}    {1,-7} {2,-6} {3}" -f $e.ProdId, $e.Build, $e.Count, $desc
}