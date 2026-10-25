# Checks an installed Phalanx's process events, side-loading check and
# idle CPU. Run from a terminal opened as administrator, after setup:
#
#   powershell -ExecutionPolicy Bypass -File tools\lab\check-installed.ps1
#
# It starts harmless programs only: copies of Windows' cmd.exe carrying
# Phalanx's test marker (detected as Test.ThreatScanner.Marker, so each
# start shows up as a detection), and a copy of ping next to a changed copy
# of IPHLPAPI.DLL (reported as side-loading). They land in History. Side-
# loading checks are turned off for one measurement and back on at the end.
# The report is written to target\lab\installed-check.txt.

param(
    [int]$ShortLived = 20,
    [int]$IdleSeconds = 60,
    [int]$Burst = 200
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot)
$cli = Join-Path $env:ProgramFiles 'Phalanx\phalanx-cli.exe'
$lab = Join-Path $env:SystemDrive 'phalanx-lab'
$outDir = Join-Path $repo 'target\lab'
$report = Join-Path $outDir 'installed-check.txt'
$events = Join-Path $lab 'events.jsonl'
New-Item -ItemType Directory -Force $outDir | Out-Null
Set-Content -Encoding utf8 $report "Phalanx installed check, $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

# Each line goes to the report at once, so a run that stops still leaves one.
function Say([string]$text) {
    Write-Host $text
    Add-Content -Encoding utf8 $report $text
}

function Get-Protection {
    & $cli service protection | Out-String | ConvertFrom-Json
}

function Set-SideLoading([bool]$on) {
    $settings = & $cli service settings | Out-String | ConvertFrom-Json
    $settings.side_loading = $on
    $json = $settings | ConvertTo-Json -Compress -Depth 5
    $hex = -join ([Text.Encoding]::UTF8.GetBytes($json) | ForEach-Object { $_.ToString('x2') })
    & $cli service set-settings --json $hex | Out-Null
    # Protection restarts with the new settings.
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        $p = Get-Protection
    } until (($p.watching -and $p.program_events) -or (Get-Date) -gt $deadline)
    Start-Sleep -Seconds 5
}

# CPU seconds the service uses over $seconds, and the share of one core.
function Measure-ServiceCpu([int]$seconds, [scriptblock]$during) {
    $service = Get-Process phalanx-service
    $before = $service.TotalProcessorTime
    $started = Get-Date
    if ($during) { & $during }
    $left = $seconds - ((Get-Date) - $started).TotalSeconds
    if ($left -gt 0) { Start-Sleep -Seconds ([int][math]::Ceiling($left)) }
    $service.Refresh()
    $used = ($service.TotalProcessorTime - $before).TotalSeconds
    $wall = ((Get-Date) - $started).TotalSeconds
    '{0:N2} s CPU in {1:N0} s ({2:N2}% of one core), working set {3:N0} MB' -f $used, $wall, (100 * $used / $wall), ($service.WorkingSet64 / 1MB)
}

try {
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this from a terminal opened as administrator.' }
if (-not (Test-Path $cli)) { throw "Phalanx is not installed ($cli not found)." }
New-Item -ItemType Directory -Force $lab | Out-Null

Say "Version: $((Get-Item $cli).VersionInfo.ProductVersion)"
Say "Service: $((Get-Service Phalanx).Status)"

# 1. Programs are seen through process events.
$p = Get-Protection
Say ''
Say "1. Protection: watching=$($p.watching) programs=$($p.programs) program_events=$($p.program_events)"
Say $(if ($p.program_events) { '   PASS: programs are seen through process events' } else { '   FAIL: programs are found by polling' })

# The service's events, for the next two checks.
Remove-Item $events -ErrorAction SilentlyContinue
$listener = Start-Process $cli -ArgumentList 'service', 'events' -RedirectStandardOutput $events -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2

# 2. Short-lived programs: each copy runs for a few milliseconds.
$marker = 'threat-scanner-test-marker-7f3a'.ToUpper()
$cmd = [IO.File]::ReadAllBytes("$env:SystemRoot\System32\cmd.exe") + [Text.Encoding]::ASCII.GetBytes($marker)
$short = Join-Path $lab 'short'
New-Item -ItemType Directory -Force $short | Out-Null
$names = @()
for ($i = 1; $i -le $ShortLived; $i++) {
    $exe = Join-Path $short ("brief-$i-" + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.exe')
    [IO.File]::WriteAllBytes($exe, $cmd)
    $names += Split-Path $exe -Leaf
}
$timings = @()
foreach ($name in $names) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Start-Process (Join-Path $short $name) -ArgumentList '/c', 'exit' -WindowStyle Hidden -Wait
    $timings += $watch.ElapsedMilliseconds
}
Start-Sleep -Seconds 10

# 3. Side-loading: signed ping next to an unsigned copy of a DLL it imports.
$side = Join-Path $lab 'sideload'
New-Item -ItemType Directory -Force $side | Out-Null
Copy-Item "$env:SystemRoot\System32\PING.EXE" (Join-Path $side 'ping.exe') -Force
$dll = [IO.File]::ReadAllBytes("$env:SystemRoot\System32\IPHLPAPI.DLL") + [Text.Encoding]::ASCII.GetBytes('phalanx side-loading test')
[IO.File]::WriteAllBytes((Join-Path $side 'IPHLPAPI.DLL'), $dll)
Start-Process (Join-Path $side 'ping.exe') -ArgumentList '-n', '1', '127.0.0.1' -WindowStyle Hidden -Wait
Start-Sleep -Seconds 10

Stop-Process $listener -ErrorAction SilentlyContinue
$seen = Get-Content $events -ErrorAction SilentlyContinue | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} }

$detected = @($names | Where-Object { $n = $_; $seen | Where-Object { $_.type -eq 'detection' -and $_.report.path -like "*\$n" } })
Say ''
Say ("2. Short-lived programs: {0} of {1} reported (each ran {2:N0}-{3:N0} ms, as Start-Process measures it)" -f $detected.Count, $names.Count, ($timings | Measure-Object -Minimum).Minimum, ($timings | Measure-Object -Maximum).Maximum)
Say $(if ($detected.Count -eq $names.Count) { '   PASS' } else { "   FAIL: missed $(@($names | Where-Object { $detected -notcontains $_ }) -join ', ')" })

$sideHit = $seen | Where-Object { $_.type -eq 'side-load' } | Select-Object -First 1
Say ''
if ($sideHit) {
    Say "3. Side-loading: PASS: $($sideHit.hit.program) loaded $($sideHit.hit.dll)"
} else {
    Say '3. Side-loading: FAIL: no side-load event'
}

# 4. CPU: idle and during a burst of program starts, side-loading on and off.
Say ''
Say "4. Service CPU (idle: $IdleSeconds s; burst: $Burst starts of cmd /c exit)"
# The service checks programs as they start; give it a moment to finish.
$burstStarts = { for ($i = 0; $i -lt $Burst; $i++) { Start-Process cmd.exe -ArgumentList '/c', 'exit' -WindowStyle Hidden -Wait }; Start-Sleep -Seconds 5 }
Say "   side-loading on,  idle:  $(Measure-ServiceCpu $IdleSeconds $null)"
Say "   side-loading on,  burst: $(Measure-ServiceCpu 1 $burstStarts)"
Set-SideLoading $false
Say "   side-loading off, idle:  $(Measure-ServiceCpu $IdleSeconds $null)"
Say "   side-loading off, burst: $(Measure-ServiceCpu 1 $burstStarts)"
Set-SideLoading $true
$p = Get-Protection
Say "   side-loading back on: program_events=$($p.program_events)"

} catch {
    Say ''
    Say "STOPPED: $($_.Exception.Message)"
    Say "   at line $($_.InvocationInfo.ScriptLineNumber): $($_.InvocationInfo.Line.Trim())"
} finally {
    if ($listener) { Stop-Process $listener -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $lab -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host "Report: $report"
}
