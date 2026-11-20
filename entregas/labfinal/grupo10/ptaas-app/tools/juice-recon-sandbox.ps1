param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'La salida ya existe' }
$suffix = [guid]::NewGuid().ToString('N')
$network = "ptaas-recon-net-$suffix"
$target = "ptaas-recon-juice-$suffix"
$image = 'bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809'
$runner = 'ptaas-attack-pilot-test:local'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$networkId = docker network create --internal $network
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear red interna' }
$targetId = $null
try {
    $targetId = docker run -d --pull never --name $target --network $network --network-alias juice-shop.lab.test --cap-drop ALL --security-opt no-new-privileges $image
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar Juice Shop' }
    $args = @('run','--rm','--pull','never','--network',$network,'--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--user','65534:65534','--pids-limit','32','--memory','128m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--env','PYTHONPATH=/app',
        '--mount',"type=bind,source=$root/runtime,target=/app/runtime,readonly",
        '--mount',"type=bind,source=$root/harness,target=/app/harness,readonly",
        '--workdir','/app',$runner,'python','-B','/app/runtime/recon.py')
    $json = docker @args
    if ($LASTEXITCODE -ne 0) { throw 'Recon falló' }
    $result = ($json -join "`n") | ConvertFrom-Json
} finally {
    if ($targetId -match '^[0-9a-f]{64}$') { docker rm -f -v $targetId | Out-Null }
    $removed = -not (docker ps -a --filter "id=$targetId" --format '{{.ID}}')
    docker network rm $networkId | Out-Null
    $networkRemoved = $LASTEXITCODE -eq 0
}
if (-not ($removed -and $networkRemoved)) { throw 'Limpieza no verificada' }
$result | Add-Member target_removed $removed
$result | Add-Member network_removed $networkRemoved
$stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew)
try { $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 8) + "`n"); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$result | ConvertTo-Json -Depth 8
