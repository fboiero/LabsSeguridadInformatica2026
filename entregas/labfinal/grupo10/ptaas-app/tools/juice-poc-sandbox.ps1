param(
    [Parameter(Mandatory=$true)][string]$PocId,
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$ParamName,
    [switch]$ApprovePoc,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference = 'Stop'
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'La salida ya existe' }
$suffix = [guid]::NewGuid().ToString('N')
$network = "ptaas-poc-net-$suffix"
$target = "ptaas-poc-juice-$suffix"
$image = if ($env:PTAAS_JUICESHOP_IMAGE) { $env:PTAAS_JUICESHOP_IMAGE } else { 'bkimminich/juice-shop:latest' }
$runner = 'ptaas-attack-pilot-test:local'
$available = @(docker image ls --format '{{.Repository}}:{{.Tag}}')
if ($available -notcontains $image) {
    docker pull $image
    if ($LASTEXITCODE -ne 0) { throw "No se pudo descargar la imagen de Juice Shop: $image" }
}
$networkId = docker network create --internal $network
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear red interna' }
$targetId = $null
try {
    $targetId = docker run -d --pull never --name $target --network $network --network-alias juice-shop.lab.test --cap-drop ALL --security-opt no-new-privileges $image
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar Juice Shop' }
    $internal = docker network inspect --format '{{.Internal}}' $networkId
    if ($LASTEXITCODE -ne 0 -or $internal -cne 'true') { throw 'Red no interna' }
    $arguments = @('run','--rm','--pull','never','-i','--network',$network,'--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--user','65534:65534','--pids-limit','32','--memory','128m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m',
        '--env','PYTHONPATH=/app',
        '--mount',"type=bind,source=$((Resolve-Path (Join-Path $PSScriptRoot '..')).Path)/runtime,target=/app/runtime,readonly",
        '--mount',"type=bind,source=$((Resolve-Path (Join-Path $PSScriptRoot '..')).Path)/harness,target=/app/harness,readonly",
        '--workdir','/app',$runner,'python','-B','/app/runtime/poc_sender.py','--poc-id',$PocId,'--base-url','http://juice-shop.lab.test:3000','--path',$Path)
    if ($ParamName) { $arguments += @('--param-name',$ParamName) }
    if ($ApprovePoc) { $arguments += '--approve' }
    $json = docker @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Sender bloqueado o falló' }
    $result = ($json -join "`n") | ConvertFrom-Json
} finally {
    if ($targetId -match '^[0-9a-f]{64}$') { docker rm -f -v $targetId | Out-Null }
    $remaining = docker ps -a --filter "id=$targetId" --format '{{.ID}}'
    $removed = -not $remaining
    docker network rm $networkId | Out-Null
    $networkRemoved = $LASTEXITCODE -eq 0
}
if (-not ($removed -and $networkRemoved)) { throw 'Limpieza no verificada' }
$result | Add-Member -NotePropertyName target_removed -NotePropertyValue $removed
$result | Add-Member -NotePropertyName network_removed -NotePropertyValue $networkRemoved
$result | Add-Member -NotePropertyName sandbox -NotePropertyValue 'ephemeral_internal_no_persistence'
$stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew)
try { $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 8) + "`n"); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$result | ConvertTo-Json -Depth 8
