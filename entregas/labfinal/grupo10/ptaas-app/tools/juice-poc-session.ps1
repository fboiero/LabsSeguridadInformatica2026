param(
    [Parameter(Mandatory=$true)][ValidateSet('Check','Stop')][string]$Action,
    [Parameter(Mandatory=$true)][string]$StateFile,
    [string]$PocId,
    [string]$Path,
    [switch]$ApprovePoc,
    [switch]$Active,
    [string]$Output
)
$ErrorActionPreference = 'Stop'
$statePath = [IO.Path]::GetFullPath($StateFile)
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runner = 'ptaas-attack-pilot-test:local'
$image = if ($env:PTAAS_JUICESHOP_IMAGE) { $env:PTAAS_JUICESHOP_IMAGE } else { 'bkimminich/juice-shop:latest' }
function Ensure-Runner {
    $images = @(docker images --format '{{.Repository}}:{{.Tag}}')
    if ($images -contains $runner) { return }
    @'
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN python -m pip install --no-cache-dir "pydantic>=2.12,<3" "pytest>=8,<10" "PyYAML>=6,<7"
'@ | docker build --tag $runner -
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo construir la imagen auxiliar del sandbox' }
}
function Start-Lab {
    if (Test-Path -LiteralPath $statePath) { return (Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json) }
    $available = @(docker image ls --format '{{.Repository}}:{{.Tag}}')
    if ($available -notcontains $image) {
        docker pull $image
        if ($LASTEXITCODE -ne 0) { throw "No se pudo descargar la imagen de Juice Shop: $image" }
    }
    $suffix = [guid]::NewGuid().ToString('N')
    $network = "ptaas-poc-net-$suffix"
    $target = "ptaas-poc-juice-$suffix"
    $networkId = docker network create --internal $network
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear red interna' }
    $targetId = docker run -d --pull never --name $target --network $network --network-alias juice-shop.lab.test --cap-drop ALL --security-opt no-new-privileges $image
    if ($LASTEXITCODE -ne 0) { docker network rm $networkId | Out-Null; throw 'No se pudo iniciar Juice Shop' }
    $state = [pscustomobject]@{ network=$network; networkId=($networkId -join ''); targetId=($targetId -join '') }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding utf8
    return $state
}
if ($Action -eq 'Stop') {
    if (Test-Path -LiteralPath $statePath) {
        $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
        docker rm -f -v $state.targetId | Out-Null
        docker network rm $state.networkId | Out-Null
        Remove-Item -LiteralPath $statePath -Force
    }
    exit 0
}
Ensure-Runner
$state = Start-Lab
$args = @('run','--rm','--pull','never','-i','--network',$state.network,'--read-only','--cap-drop','ALL',
    '--security-opt','no-new-privileges','--user','65534:65534','--pids-limit','32','--memory','128m',
    '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--env','PYTHONPATH=/app',
    '--mount',"type=bind,source=$root/runtime,target=/app/runtime,readonly",
    '--mount',"type=bind,source=$root/harness,target=/app/harness,readonly",
    '--workdir','/app',$runner,'python','-B','/app/runtime/poc_sender.py','--poc-id',$PocId,
    '--base-url','http://juice-shop.lab.test:3000','--path',$Path)
if ($ApprovePoc) { $args += '--approve' }
if ($Active) { $args += '--active' }
$json = docker @args
if ($LASTEXITCODE -ne 0) { throw 'Sender bloqueado o falló' }
$json | Set-Content -LiteralPath $Output -Encoding utf8
