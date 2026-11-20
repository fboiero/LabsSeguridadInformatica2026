param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $outputPath) { throw 'La salida ya existe' }
$baseName = [IO.Path]::GetFileNameWithoutExtension($outputPath)
$suffix = [guid]::NewGuid().ToString('N')
$network = "ptaas-integrated-net-$suffix"
$target = "ptaas-integrated-juice-$suffix"
$image = 'bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809'
$networkId = docker network create --internal $network
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear red interna' }
$targetId = $null
$audit = Join-Path (Split-Path $outputPath) ($baseName + '.sqlite')
$ab = Join-Path (Split-Path $outputPath) ($baseName + '-ab.json')
try {
    $targetId = docker run -d --pull never --name $target --network $network --network-alias juice-shop.lab.test --cap-drop ALL --security-opt no-new-privileges $image
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar Juice Shop' }
    Start-Sleep -Seconds 15
    & python -m runtime.integrated_host --network $network --audit $audit --output $ab
    if ($LASTEXITCODE -ne 0) { throw 'Loop A/B bloqueado' }
    $runner = 'ptaas-attack-pilot-test:local'
    $args = @('run','--rm','--pull','never','-i','--network',$network,'--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--user','65534:65534','--pids-limit','32','--memory','128m',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--env','PYTHONPATH=/app',
        '--mount',"type=bind,source=$root/runtime,target=/app/runtime,readonly",
        '--mount',"type=bind,source=$root/harness,target=/app/harness,readonly",
        '--workdir','/app',$runner,'python','-B','/app/runtime/poc_sender.py','--poc-id','POC-CSP-001',
        '--base-url','http://juice-shop.lab.test:3000','--path','/','--approve')
    $c = docker @args
    if ($LASTEXITCODE -ne 0) { throw 'Loop C bloqueado' }
    $cResult = ($c -join "`n") | ConvertFrom-Json
    $cStatus = if ($cResult.status) { $cResult.status } else { 'unknown' }
    $final = Join-Path (Split-Path $audit) ($baseName + '-c.json')
    & python -m runtime.integrated_finalize --audit $audit --status $cStatus --output $final
    if ($LASTEXITCODE -ne 0) { throw 'Bitácora integrada bloqueada' }
    $result = [ordered]@{state='INTEGRATED_WITH_LIMITATIONS'; loops=@{A_B=(Get-Content $ab -Raw | ConvertFrom-Json); C=$cResult}; audit_file=(Split-Path $audit -Leaf); final_audit=(Get-Content $final -Raw | ConvertFrom-Json); target_removed=$false; network_removed=$false}
} finally {
    if ($targetId -match '^[0-9a-f]{64}$') { docker rm -f -v $targetId | Out-Null }
    $removed = -not (docker ps -a --filter "id=$targetId" --format '{{.ID}}')
    docker network rm $networkId | Out-Null
    $networkRemoved = $LASTEXITCODE -eq 0
}
if (-not ($removed -and $networkRemoved)) { throw 'Limpieza no verificada' }
$result.target_removed = $removed
$result.network_removed = $networkRemoved
$stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew)
try { $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 15) + "`n"); $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
$result | ConvertTo-Json -Depth 15
