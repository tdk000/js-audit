# =============================================================
#  JsAudit.ps1 - audit of embedded JS engines on Windows
#  Looks for: Electron, CEF, WebView2, Chromium-embedded,
#             Node.js, full browsers, system JScript (WSH/MSHTA)
#  Report: HTML histogram (no JS inside), CSV, JSON
#  Portable: run via JsAudit.cmd (double-click) on any Windows 10/11 PC
# =============================================================

param(
    [string]$OutDir = '',
    [switch]$NoOpen
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$machine = $env:COMPUTERNAME
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$tag = $machine + '_' + (Get-Date -Format 'yyyyMMdd_HHmmss')

if (-not $OutDir) {
    if ($PSScriptRoot) { $OutDir = Join-Path $PSScriptRoot 'out' } else { $OutDir = Join-Path (Get-Location) 'out' }
}
# portable fallback: read-only media (USB stick, network share) -> %TEMP%
try {
    New-Item -ItemType Directory -Force -Path $OutDir -ErrorAction Stop | Out-Null
    $probe = Join-Path $OutDir '.writetest'
    [IO.File]::WriteAllText($probe, 'x')
    [IO.File]::Delete($probe)
} catch {
    $OutDir = Join-Path $env:TEMP ('JsAudit_' + $tag)
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    Write-Host "[warn] output folder is not writable, reports go to: $OutDir"
}

function Enc([string]$s) {
    if (-not $s) { return '' }
    return $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
}

function TextBar([string]$label, [int]$count, [int]$max) {
    $w = 0
    if ($max -gt 0) { $w = [int][math]::Round(38.0 * $count / $max) }
    if ($w -lt 1) { $w = 1 }
    $bar = ('#' * $w)
    Write-Host ("  {0,-36} {1,-40} {2}" -f $label, $bar, $count)
}

function Chart([string]$title, $rows) {
    if (-not $rows -or @($rows).Count -eq 0) {
        return "<h2>" + (Enc $title) + "</h2><p class='muted'>Нет данных.</p>"
    }
    $max = 1
    foreach ($r in $rows) { if ($r.Count -gt $max) { $max = $r.Count } }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<h2>" + (Enc $title) + "</h2>`n<table class=`"chart`">`n")
    foreach ($r in $rows) {
        $pct = [int][math]::Round(100.0 * $r.Count / $max)
        [void]$sb.Append("<tr><td class=`"lbl`">" + (Enc ([string]$r.Label)) +
            "</td><td class=`"cell`"><div class=`"bar`" style=`"width:$pct%`"></div></td>" +
            "<td class=`"num`">" + $r.Count + "</td></tr>`n")
    }
    [void]$sb.Append("</table>`n")
    return $sb.ToString()
}

function Scan-Root([string]$scanPath, [string]$recordRoot) {
    Write-Host "[scan] $scanPath ..."
    Get-ChildItem -LiteralPath $scanPath -Recurse -Force -File -Depth 7 -ErrorAction SilentlyContinue |
        ForEach-Object {
            $n = $_.Name.ToLower()
            if ($script:markerSet.Contains($n)) {
                $script:findings.Add([pscustomobject]@{ Path = $_.FullName; Marker = $n; Root = $recordRoot })
            }
        }
}

Write-Host "=== JsAudit: audit of embedded JS engines ==="
Write-Host "Machine: $machine   Start: $stamp"

# ------------------------------------------------------------
# 1. Marker files in standard install roots
# ------------------------------------------------------------
$roots = @()
foreach ($r in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))) {
    if ($r -and (Test-Path -LiteralPath $r)) { $roots += $r }
}

$markerSet = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($m in @('app.asar','default_app.asar','chrome_elf.dll','libcef.dll','cef.pak','webview2loader.dll','node.exe','deno.exe','bun.exe','nw.exe','nw.dll')) {
    [void]$markerSet.Add($m)
}

$findings = New-Object System.Collections.Generic.List[object]

foreach ($r in $roots) { Scan-Root $r $r }

# %LOCALAPPDATA% top-level children (Discord/WhatsApp-style installs live here),
# heavy data dirs excluded
$localExclude = @('Microsoft','Google','Packages','Temp','Mozilla','npm-cache','pip',
    'CrashDumps','D3DSCache','Comms','SquirrelTemp','Chromium','cache','Yandex',
    'Vivaldi','BraveSoftware','Opera Software','Opera Software AS','Programs',
    'Microsoft Edge','Microsoft OneDrive')
foreach ($child in (Get-ChildItem -LiteralPath $env:LOCALAPPDATA -Directory -Force -ErrorAction SilentlyContinue)) {
    if ($localExclude -contains $child.Name) { continue }
    Scan-Root $child.FullName $env:LOCALAPPDATA
}

# per-user installs hidden inside excluded data dirs: classic Teams (Electron)
# lives in LOCALAPPDATA\Microsoft\Teams, per-user Chrome in
# LOCALAPPDATA\Google\Chrome\Application. Their data subdirs stay excluded.
$msDataExclude = @('Edge','EdgeWebView','EdgeUpdate','EdgeCore','OneDrive','WindowsApps',
    'Office','SquirrelTemp','Temp','TeamsMeetingAddin','MicrosoftEdgeBackups')
foreach ($child in (Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft') -Directory -Force -ErrorAction SilentlyContinue)) {
    if ($msDataExclude -contains $child.Name) { continue }
    Scan-Root $child.FullName (Join-Path $env:LOCALAPPDATA 'Microsoft')
}
$chromeApp = Join-Path $env:LOCALAPPDATA 'Google\Chrome\Application'
if (Test-Path -LiteralPath $chromeApp) { Scan-Root $chromeApp (Join-Path $env:LOCALAPPDATA 'Google') }
Write-Host ("[scan] total findings: {0}" -f $findings.Count)

# ------------------------------------------------------------
# 2. Group findings into applications
# ------------------------------------------------------------
$interNames = @('Google','Microsoft','Mozilla','Chromium','BraveSoftware',
    'Opera Software','Opera','Vivaldi','Yandex','VK','NVIDIA Corporation')

$apps = @{}
foreach ($f in $findings) {
    $rel = $f.Path.Substring($f.Root.Length).TrimStart('\')
    $parts = $rel -split '\\'
    if ($parts.Count -lt 2) { continue }
    $p0 = $parts[0]
    if (($interNames -contains $p0) -and ($parts.Count -ge 3)) { $name = "$p0 $($parts[1])" } else { $name = $p0 }
    $key = $f.Root + '|' + $name
    if (-not $apps.ContainsKey($key)) {
        $apps[$key] = @{ Name = $name; Root = $f.Root; Markers = @{}; Evidence = (New-Object System.Collections.Generic.List[string]) }
    }
    $apps[$key].Markers[$f.Marker] = $true
    if ($apps[$key].Evidence.Count -lt 5) { $apps[$key].Evidence.Add($f.Path) }
}

$browserRe = '\b(chrome|chromium|msedge|edge|firefox|opera|brave|vivaldi|yandex)'

$appList = New-Object System.Collections.Generic.List[object]
foreach ($a in $apps.Values) {
    $m = $a.Markers.Keys
    $name = $a.Name
    $cats = @()
    if ($name -match 'edgewebview') { $cats += 'WebView2Runtime' }
    elseif (($m -contains 'app.asar') -or ($m -contains 'default_app.asar')) { $cats += 'Electron' }
    elseif ($name -match $browserRe) { $cats += 'Browser' }
    elseif (($m -contains 'libcef.dll') -or ($m -contains 'cef.pak')) { $cats += 'CEF' }
    elseif ($m -contains 'chrome_elf.dll') { $cats += 'Chromium-embedded' }
    elseif ($m -contains 'deno.exe') { $cats += 'Deno' }
    elseif ($m -contains 'bun.exe') { $cats += 'Bun' }
    elseif (($m -contains 'nw.dll') -or ($m -contains 'nw.exe')) { $cats += 'NW.js' }
    else { $cats += 'Other' }
    if (($cats[0] -ne 'WebView2Runtime') -and ($m -contains 'webview2loader.dll')) { $cats += 'WebView2' }
    if ($m -contains 'node.exe') { $cats += 'Node' }
    if ($cats[0] -eq 'Other') {
        if ($cats.Count -gt 1) { $cats = @($cats | Select-Object -Skip 1) } else { continue }
    }
    $appList.Add([pscustomobject]@{
        Name     = $name
        Category = ($cats -join '+')
        Root     = $a.Root
        Markers  = (($m | Sort-Object) -join ', ')
        Evidence = (($a.Evidence | Select-Object -First 3) -join ';  ')
    })
}
$appList = @($appList | Sort-Object Name)
Write-Host ("[apps] applications with JS engines found: {0}" -f $appList.Count)

# ------------------------------------------------------------
# 3. WebView2: runtime, active hosts (EBWebView), policies
# ------------------------------------------------------------
$wvRuntime = @()
foreach ($base in @(
    (Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView\Application'),
    (Join-Path $env:ProgramFiles 'Microsoft\EdgeWebView\Application'),
    (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\EdgeWebView\Application'))) {
    if ($base -and (Test-Path -LiteralPath $base)) {
        $wvRuntime += (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    }
}
$wvRuntime = @($wvRuntime | Sort-Object -Unique)

$wvHosts = New-Object System.Collections.Generic.List[object]
Get-ChildItem -LiteralPath $env:LOCALAPPDATA -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Name -in @('Microsoft','Packages')) { return }
    $p = Join-Path $_.FullName 'EBWebView'
    if (Test-Path -LiteralPath $p) {
        $wvHosts.Add([pscustomobject]@{ Name = $_.Name; Kind = 'EBWebView'; Path = $p })
    }
}
$pkgs = Join-Path $env:LOCALAPPDATA 'Packages'
if (Test-Path -LiteralPath $pkgs) {
    Get-ChildItem -LiteralPath $pkgs -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($sub in @('AC\EBWebView','LocalState\EBWebView','LocalCache\Local\EBWebView')) {
            $p = Join-Path $_.FullName $sub
            if (Test-Path -LiteralPath $p) {
                $wvHosts.Add([pscustomobject]@{ Name = $_.Name; Kind = "EBWebView ($sub)"; Path = $p })
                break
            }
        }
    }
}

$policyRows = New-Object System.Collections.Generic.List[object]
foreach ($hive in @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebView2',
    'HKCU:\SOFTWARE\Policies\Microsoft\Edge\WebView2',
    'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
    'HKCU:\SOFTWARE\Policies\Microsoft\Edge')) {
    if (-not (Test-Path -LiteralPath $hive)) { continue }
    $k = Get-Item -LiteralPath $hive
    foreach ($vn in $k.GetValueNames()) {
        $policyRows.Add([pscustomobject]@{ Key = $hive; Name = $vn; Value = [string]$k.GetValue($vn) })
    }
    foreach ($sn in $k.GetSubKeyNames()) {
        $sk = Get-Item -LiteralPath (Join-Path $hive $sn)
        foreach ($vn in $sk.GetValueNames()) {
            $policyRows.Add([pscustomobject]@{ Key = "$hive\$sn"; Name = $vn; Value = [string]$sk.GetValue($vn) })
        }
    }
}

# ------------------------------------------------------------
# 4. Live processes
# ------------------------------------------------------------
Write-Host "[proc] process snapshot..."
$procs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ Name = $_.Name; Pid = $_.ProcessId; PPid = $_.ParentProcessId; Exe = $_.ExecutablePath }
}
$byId = @{}
foreach ($p in $procs) { $byId[$p.Pid] = $p }

$live = New-Object System.Collections.Generic.List[object]
$asarChecked = @{}
foreach ($p in $procs) {
    if (-not $p.Name) { continue }
    $n = $p.Name.ToLower()
    $kind = ''
    if ($n -eq 'msedgewebview2.exe') {
        $cur = $byId[$p.PPid]; $hops = 0
        while ($cur -and ($cur.Name -ieq 'msedgewebview2.exe') -and ($hops -lt 8)) {
            $cur = $byId[$cur.PPid]; $hops++
        }
        $hostName = if ($cur) { $cur.Name } else { 'unknown' }
        $kind = "WebView2 host: $hostName"
    }
    elseif ($n -eq 'node.exe') { $kind = 'Node.js' }
    elseif ($n -eq 'wscript.exe' -or $n -eq 'cscript.exe') { $kind = 'WSH (JScript)' }
    elseif ($n -eq 'mshta.exe') { $kind = 'MSHTA (JScript)' }
    elseif ($n -match $browserRe) { $kind = 'Browser' }
    elseif ($p.Exe) {
        $dir = Split-Path $p.Exe -Parent
        if (-not $asarChecked.ContainsKey($dir)) {
            $asarChecked[$dir] = (Test-Path -LiteralPath (Join-Path $dir 'resources\app.asar'))
        }
        if ($asarChecked[$dir]) { $kind = 'Electron' }
    }
    if ($kind) {
        $live.Add([pscustomobject]@{ Kind = $kind; Name = $p.Name; Pid = $p.Pid; Exe = [string]$p.Exe })
    }
}
Write-Host ("[proc] live JS processes: {0}" -f $live.Count)

$nodeOnPath = Get-Command node.exe -ErrorAction SilentlyContinue
$nodeVer = ''
if ($nodeOnPath) { try { $nodeVer = [string](& node.exe --version 2>$null) } catch { $nodeVer = '' } }
$nodePathText = 'нет'
if ($nodeOnPath) { $nodePathText = "да ($nodeVer)" }

# ------------------------------------------------------------
# 5. Counts and exports
# ------------------------------------------------------------
$engineCounts = [ordered]@{}
foreach ($e in @('Electron','CEF','WebView2','WebView2Runtime','Chromium-embedded','Node','Deno','Bun','NW.js','Browser')) {
    $engineCounts[$e] = @($appList | Where-Object { $_.Category -match [regex]::Escape($e) }).Count
}
$engineCounts['WebView2 hosts (EBWebView)'] = @($wvHosts | ForEach-Object { $_.Name } | Sort-Object -Unique).Count

$liveCounts = [ordered]@{}
foreach ($g in ($live | Group-Object Kind)) { $liveCounts[$g.Name] = $g.Count }

$jsonPath  = Join-Path $OutDir ("js_audit_" + $tag + ".json")
$csvPath   = Join-Path $OutDir ("js_audit_" + $tag + ".csv")
$htmlPath  = Join-Path $OutDir ("js_audit_report_" + $tag + ".html")

$data = [ordered]@{
    machine                  = $machine
    timestamp                = $stamp
    scan_roots               = $roots
    engines_by_apps          = $engineCounts
    live_processes_by_kind   = $liveCounts
    apps                     = $appList
    webview2_runtime_versions= $wvRuntime
    webview2_hosts           = $wvHosts
    policies                 = $policyRows
    live_processes           = $live
}
$json = $data | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))
$appList | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

# ------------------------------------------------------------
# 6. HTML report (histograms, zero JavaScript)
# ------------------------------------------------------------
$engineRows = New-Object System.Collections.Generic.List[object]
foreach ($k in $engineCounts.Keys) { $engineRows.Add([pscustomobject]@{ Label = $k; Count = [int]$engineCounts[$k] }) }
$engineRows = @($engineRows | Sort-Object Count -Descending)

$liveRows = New-Object System.Collections.Generic.List[object]
foreach ($k in $liveCounts.Keys) { $liveRows.Add([pscustomobject]@{ Label = $k; Count = [int]$liveCounts[$k] }) }
$liveRows = @($liveRows | Sort-Object Count -Descending)

$chartEngines = Chart 'Гистограмма: движки → число приложений' $engineRows
$chartLive    = Chart 'Гистограмма: JS-процессы прямо сейчас (по типам)' $liveRows

$appsRows = ''
foreach ($a in $appList) {
    $appsRows += "<tr><td>" + (Enc $a.Name) + "</td><td>" + (Enc $a.Category) +
        "</td><td class='mono small'>" + (Enc $a.Root) +
        "</td><td class='mono small'>" + (Enc $a.Evidence) + "</td></tr>`n"
}
$appsHtml = ''
if ($appList.Count -gt 0) {
    $appsHtml = "<table><tr><th>Приложение</th><th>Движок</th><th>Корень</th><th>Доказательства (маркер-файлы)</th></tr>$appsRows</table>"
} else {
    $appsHtml = "<p class='muted'>Приложений с вшитыми движками не найдено.</p>"
}

$wvRows = ''
foreach ($w in ($wvHosts | Sort-Object Name)) {
    $wvRows += "<tr><td>" + (Enc $w.Name) + "</td><td class='mono small'>" + (Enc $w.Path) + "</td></tr>`n"
}
$wvHtml = ''
if ($wvHosts.Count -gt 0) {
    $wvHtml = "<table><tr><th>Приложение</th><th>Папка данных WebView2</th></tr>$wvRows</table>"
} else {
    $wvHtml = "<p class='muted'>Активных хостов WebView2 не найдено.</p>"
}

$liveRowsHtml = ''
foreach ($l in ($live | Sort-Object Kind, Name)) {
    $liveRowsHtml += "<tr><td>" + (Enc $l.Kind) + "</td><td>" + (Enc $l.Name) +
        "</td><td>" + $l.Pid + "</td><td class='mono small'>" + (Enc ([string]$l.Exe)) + "</td></tr>`n"
}
$liveHtml = ''
if ($live.Count -gt 0) {
    $liveHtml = "<table><tr><th>Тип</th><th>Процесс</th><th>PID</th><th>Путь</th></tr>$liveRowsHtml</table>"
} else {
    $liveHtml = "<p class='muted'>Сейчас ни одного JS-процесса не запущено.</p>"
}

$polRows = ''
foreach ($pl in $policyRows) {
    $polRows += "<tr><td class='mono small'>" + (Enc $pl.Key) + "</td><td>" + (Enc $pl.Name) +
        "</td><td>" + (Enc $pl.Value) + "</td></tr>`n"
}
$polHtml = ''
if ($policyRows.Count -gt 0) {
    $polHtml = "<table><tr><th>Ключ</th><th>Политика</th><th>Значение</th></tr>$polRows</table>"
} else {
    $polHtml = "<p class='muted'>Политики WebView2/Edge не заданы — поле чистое, харднинг можно накатывать с нуля.</p>"
}

$rtHtml = ''
if ($wvRuntime.Count -gt 0) {
    $rtHtml = "<p>WebView2 Runtime установлен, версии: <b>" + ($wvRuntime -join ', ') + "</b></p>"
} else {
    $rtHtml = "<p class='muted'>WebView2 Runtime не найден.</p>"
}

$html = @"
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Аудит JS-движков — $machine</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 960px; margin: 24px auto; color: #1a1a1a; padding: 0 12px; }
h1 { font-size: 22px; margin-bottom: 2px; }
h2 { font-size: 17px; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
.sub { color: #777; font-size: 13px; margin-bottom: 18px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin-top: 8px; }
th, td { border: 1px solid #ddd; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #f2f2f2; }
table.chart, table.chart tr, table.chart td { border: none; }
table.chart td { padding: 3px 6px; }
.lbl { width: 300px; }
.cell { width: auto; min-width: 200px; }
.bar { background: #3b6ea5; height: 16px; min-width: 3px; border-radius: 2px; display: inline-block; }
.num { width: 60px; text-align: right; font-weight: bold; white-space: nowrap; }
.mono { font-family: Consolas, monospace; }
.small { font-size: 11px; color: #555; }
.muted { color: #777; }
.summary { background: #eef4fb; border: 1px solid #cddcf0; border-radius: 6px; padding: 10px 14px; font-size: 14px; }
ul { font-size: 13px; }
</style>
</head>
<body>
<h1>Аудит JS-движков в системе</h1>
<div class="sub">Хост: $machine &middot; Дата: $stamp &middot; Скрипт: JsAudit.ps1</div>
<div class="summary">
Приложений с вшитым JS-движком: <b>$($appList.Count)</b> &middot;
JS-процессов сейчас: <b>$($live.Count)</b> &middot;
Активных хостов WebView2: <b>$($wvHosts.Count)</b> &middot;
Node.js на PATH: <b>$nodePathText</b>
</div>
$chartEngines
$chartLive
<h2>WebView2 Runtime</h2>
$rtHtml
<h2>Политики WebView2 / Edge (реестр)</h2>
$polHtml
<h2>Приложения с JS-движками</h2>
$appsHtml
<h2>Хосты WebView2 (папки EBWebView)</h2>
$wvHtml
<h2>JS-процессы сейчас</h2>
$liveHtml
<h2>Примечания</h2>
<ul>
<li><b>Electron</b> — приложение целиком написано на JS поверх Chromium (маркер app.asar): заблокировать в нём JS = сломать приложение.</li>
<li><b>CEF</b> — Chromium Embedded Framework, вшитый браузер для части интерфейса.</li>
<li><b>WebView2</b> — системный рантайм Edge; JS здесь управляется политиками реестра — это и есть точка контроля.</li>
<li><b>Firefox</b> тоже исполняет JS, но на движке SpiderMonkey (не V8); учтён в категории Browser.</li>
<li><b>WSH / MSHTA</b> — системный JScript Windows, работает вне всяких браузеров (двойной клик по .js/.hta).</li>
<li>Ограничения: сканировались Program Files, Program Files (x86), %LOCALAPPDATA%\Programs и верхний уровень %LOCALAPPDATA% (глубина 7, тяжёлые каталоги данных исключены). Приложения в нестандартных местах видны только если запущены прямо сейчас (см. таблицу процессов).</li>
<li>Отчёт собран без единой строки JavaScript — только HTML + CSS.</li>
</ul>
</body>
</html>
"@
$html | Out-File -LiteralPath $htmlPath -Encoding utf8

# ------------------------------------------------------------
# 7. Console summary
# ------------------------------------------------------------
Write-Host ""
Write-Host "=== Histogram: engines -> apps ==="
$maxE = 1
foreach ($v in $engineCounts.Values) { if ($v -gt $maxE) { $maxE = $v } }
foreach ($k in $engineCounts.Keys) { TextBar $k ([int]$engineCounts[$k]) $maxE }

Write-Host ""
Write-Host "=== Histogram: live JS processes ==="
$maxL = 1
foreach ($v in $liveCounts.Values) { if ($v -gt $maxL) { $maxL = $v } }
foreach ($k in $liveCounts.Keys) { TextBar $k ([int]$liveCounts[$k]) $maxL }

Write-Host ""
Write-Host "Report: $htmlPath"
Write-Host "CSV:    $csvPath"
Write-Host "JSON:   $jsonPath"
Write-Host ("Done in {0:n1} s" -f $sw.Elapsed.TotalSeconds)

if (-not $NoOpen) {
    try { Start-Process -FilePath $htmlPath } catch { }
}
