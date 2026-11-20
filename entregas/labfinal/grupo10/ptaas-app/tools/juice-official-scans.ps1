param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'La salida ya existe' }
$suffix = [guid]::NewGuid().ToString('N')
$network = "ptaas-official-net-$suffix"
$target = "ptaas-official-juice-$suffix"
$image = 'bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809'
$networkId = docker network create --internal $network
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear red interna' }
$targetId = $null
try {
    $targetId = docker run -d --pull never --name $target --network $network --network-alias juice-shop.lab.test --cap-drop ALL --security-opt no-new-privileges $image
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar Juice Shop' }
    Start-Sleep -Seconds 15
    $json = & python -m runtime.official_tools --network $network
    if ($LASTEXITCODE -ne 0) { throw 'Los scanners oficiales fallaron' }
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
try { $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 10) + "`n"); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$result | ConvertTo-Json -Depth 10
