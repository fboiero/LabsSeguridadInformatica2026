param(
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$Bandit,
    [string]$Context,
    [string]$ApprovedSha256
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$module = Join-Path $root 'runtime/delivery.py'
$image = 'python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b'
$export = $PSBoundParameters.ContainsKey('ApprovedSha256')
if (-not $export) {
    $build = @('-B','-m','runtime.evidence_quality','--repo',$root,'--output',$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output))
    if ($Bandit) { $build += @('--bandit',(Resolve-Path -LiteralPath $Bandit).Path) }
    if ($Context) { $build += @('--context',(Resolve-Path -LiteralPath $Context).Path) }
    Push-Location -LiteralPath $root
    try {
        & (Join-Path $root '.venv/Scripts/python.exe') @build
        if ($LASTEXITCODE -ne 0) { throw 'No se pudo generar el borrador' }
    } finally { Pop-Location }
} elseif ($ApprovedSha256 -cnotmatch '^[0-9a-f]{64}$') { throw 'Hash de aprobación inválido' }
$folder = (Resolve-Path -LiteralPath $Output).Path
$receipt = Join-Path $folder 'sandbox-receipt.json'
$destination = Join-Path $folder 'defectdojo-generic.json'
if ($export -and (Test-Path -LiteralPath $destination)) { throw 'La exportación ya existe' }
if (-not $export -and (Test-Path -LiteralPath $receipt)) { throw 'El recibo ya existe' }
$argv = @('run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--user','65534:65534','--pids-limit','32','--memory','128m',
    '--mount',"type=bind,source=$module,target=/delivery.py,readonly",
    '--mount',"type=bind,source=$folder/decisiones.json,target=/decisions.json,readonly",
    '--mount',"type=bind,source=$folder/LEEME.md,target=/draft.md,readonly",
    $image,'python','-I','-B','/delivery.py','/decisions.json','/draft.md')
if ($export) { $argv += @('--approve-sha256',$ApprovedSha256) }
$json = docker @argv
if ($LASTEXITCODE -ne 0) { throw 'La validación documental falló. No se exportó.' }
$result = ($json -join "`n") | ConvertFrom-Json
if ($export) {
    $path = $destination
    $content = ConvertTo-Json -InputObject $result.generic_import -Depth 6
} else {
    $path = $receipt
    $content = $json -join "`n"
}
$stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($content + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
} finally { $stream.Dispose() }
$result | Select-Object state, review_sha256, validated_cases, publication
