# Watches the UDP ports the hook cares about, and reports which process holds them.
#
# This answers "does chusanApp bind 50201?" WITHOUT the hook DLL loaded, which is the
# one thing the hook's own logs cannot answer: the log only exists when the DLL is
# present, so it can never tell us whether the DLL is required for the bind or merely
# interferes with it.
#
# Run this FIRST, then start the game (via segatools, with the hook DLL renamed away).
# The bind has been observed at +74s to +105s after launch, so give it a few minutes.
#
#   pwsh -File tools\watch_bind.ps1 -Seconds 300
#
# Stop early with Ctrl+C; partial results are printed as they happen.

param(
    [int]$Seconds = 300,
    [int]$IntervalMs = 250,
    [int[]]$Ports = @(50200, 50201, 50202, 40110, 40112)
)

$ErrorActionPreference = 'Continue'

function Get-Bindings {
    param([int[]]$Ports)
    $out = @{}
    try {
        Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $Ports -contains $_.LocalPort } | ForEach-Object {
            $key = "{0}:{1}" -f $_.LocalAddress, $_.LocalPort
            $proc = ''
            try { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch { }
            $out[$key] = [pscustomobject]@{ Pid = $_.OwningProcess; Proc = $proc }
        }
    } catch {
        # Get-NetUDPEndpoint can fail without the IPHelper service; fall back to netstat.
        $raw = & netstat -ano -p UDP 2>$null
        foreach ($line in $raw) {
            if ($line -notmatch '^\s*UDP\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$') { continue }
            $port = [int]$Matches[2]
            if ($Ports -notcontains $port) { continue }
            $pid_ = [int]$Matches[4]
            $proc = ''
            try { $proc = (Get-Process -Id $pid_ -ErrorAction SilentlyContinue).ProcessName } catch { }
            $out["{0}:{1}" -f $Matches[1], $port] = [pscustomobject]@{ Pid = $pid_; Proc = $proc }
        }
    }
    return $out
}

$deadline = (Get-Date).AddSeconds($Seconds)
$previous = @{}
$seen = $false

Write-Host "watching UDP $($Ports -join ',') for $Seconds s (poll ${IntervalMs}ms)" -ForegroundColor Cyan
Write-Host "start the game now" -ForegroundColor Yellow
Write-Host ""

while ((Get-Date) -lt $deadline) {
    $now = Get-Bindings -Ports $Ports

    foreach ($key in $now.Keys) {
        if (-not $previous.ContainsKey($key)) {
            $b = $now[$key]
            $addr = $key.Split(':')[0]
            $port = $key.Split(':')[1]
            $tag = if ($addr -eq '0.0.0.0' -or $addr -eq '::') { 'WILDCARD' } else { 'INTERFACE' }
            Write-Host ("{0:HH:mm:ss.fff}  BOUND  {1,-8} {2,-22} pid={3,-6} {4}" -f (Get-Date), $tag, $key, $b.Pid, $b.Proc) -ForegroundColor Green
            $seen = $true
        }
    }
    foreach ($key in $previous.Keys) {
        if (-not $now.ContainsKey($key)) {
            Write-Host ("{0:HH:mm:ss.fff}  released {1}" -f (Get-Date), $key) -ForegroundColor DarkGray
        }
    }
    $previous = $now
    Start-Sleep -Milliseconds $IntervalMs
}

Write-Host ""
if ($seen) {
    Write-Host "RESULT: something bound at least one watched port." -ForegroundColor Green
} else {
    Write-Host "RESULT: nothing bound any watched port during $Seconds s." -ForegroundColor Yellow
    Write-Host "Either the game never reached that state, or it never binds without the hook." -ForegroundColor DarkGray
}
