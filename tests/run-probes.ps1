# Runs every probe this repository builds, and fails if any of them disagrees.
#
# This is the list, in one place, because it is consulted from two: the pull-request workflow
# wants it as feedback on a change, and the release workflow wants it as the gate a tag has to
# pass. Two copies would drift, and the copy that drifts is always the one nobody reads - a
# probe added to the build and to one workflow is silently not run by the other.
#
# Order matters only for the reader's patience: the smoke tests take a second and cover the
# DLL loading at all, so a build that cannot inject is reported before the probes that spend
# their time on log content. Every case runs even after a failure, because a change that
# breaks one thing often breaks its neighbour and one CI run should say so.
#
# Usage: pwsh -File tests\run-probes.ps1   (from the repository root, after build.bat)

$ErrorActionPreference = 'Stop'

# A failing probe must be a result to record, not an exception that ends the run. Under
# `shell: pwsh` in GitHub Actions, $ErrorActionPreference is Stop, and in PowerShell 7.4 and
# later a nonzero native exit becomes a terminating error through
# $PSNativeCommandUseErrorActionPreference - which would abort this script on the first
# disagreement and hide the other four results. Turning it off here keeps the exit code in
# $LASTEXITCODE, where the loop below reads it.
$PSNativeCommandUseErrorActionPreference = $false

$cases = @(
    @{ Name = 'smoke test (x64)'
       Exe = 'build\network_hook_smoketest_x64.exe'
       Arguments = @('build\chusan_network_hook_x64.dll') },
    @{ Name = 'smoke test (x86)'
       Exe = 'build\network_hook_smoketest_x86.exe'
       Arguments = @('build\chusan_network_hook_x86.dll') },
    @{ Name = 'ICMP hook'
       Exe = 'build\probe_icmp_x64.exe'
       Arguments = @() },
    @{ Name = 'log levels and LAN Install virtualisation'
       Exe = 'build\probe_logging_x64.exe'
       Arguments = @('build\chusan_network_hook_x64.dll') },
    @{ Name = 'network ownership'
       Exe = 'build\probe_ownership_x64.exe'
       Arguments = @('build\chusan_network_hook_x64.dll') }
)

$failures = @()

foreach ($case in $cases) {
    Write-Host "== $($case.Name)"
    if (-not (Test-Path -LiteralPath $case.Exe)) {
        # A missing executable is a build problem, not a test result, and saying which one is
        # missing is more useful than the shell's own error.
        Write-Host "   missing $($case.Exe): build.bat did not produce it"
        $failures += "$($case.Name) (not built)"
        continue
    }
    & ".\$($case.Exe)" @($case.Arguments)
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   exited $LASTEXITCODE"
        $failures += "$($case.Name) (exit $LASTEXITCODE)"
    }
}

if ($failures.Count -ne 0) {
    Write-Host ''
    Write-Host "FAILED: $($failures.Count) of $($cases.Count) probe(s) disagreed"
    foreach ($failure in $failures) { Write-Host "  $failure" }
    exit 1
}

Write-Host ''
Write-Host "PASS: all $($cases.Count) probes agreed"
