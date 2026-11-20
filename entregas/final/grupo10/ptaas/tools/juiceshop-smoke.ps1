param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if (Test-Path -LiteralPath $path) { throw 'La salida ya existe' }
$suffix = [guid]::NewGuid().ToString('N')
$network = "ptaas-juice-net-$suffix"
$target = "ptaas-juice-$suffix"
$image = 'bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809'
$runner = 'python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b'
$probe = @'
import http.client, json, time
for _ in range(15):
    conn = http.client.HTTPConnection('juiceshop.lab.test', 3000, timeout=2)
    try:
        conn.request('GET', '/')
        response = conn.getresponse()
        print(json.dumps(dict(method='GET', path='/', status=response.status)))
        raise SystemExit(0 if response.status == 200 else 2)
    except OSError:
        time.sleep(1)
    finally:
        conn.close()
raise SystemExit(3)
'@
$networkId = docker network create --internal $network
if ($LASTEXITCODE -ne 0) { throw 'No se pudo crear la red aislada' }
$containerId = $null
$removed = $false
$networkRemoved = $false
try {
    $containerId = docker run -d --pull never --name $target --network $network --network-alias juiceshop.lab.test --cap-drop ALL --security-opt no-new-privileges $image
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo iniciar Juice Shop' }
    $internal = docker network inspect --format '{{.Internal}}' $networkId
    if ($LASTEXITCODE -ne 0 -or $internal -cne 'true') { throw 'Red no verificada' }
    $config = docker inspect --format '{{json .HostConfig.PortBindings}}' $containerId
    if ($LASTEXITCODE -ne 0 -or $config -notin @('{}','null')) { throw 'Puertos publicados o no verificables' }
    $imageId = docker inspect --format '{{.Image}}' $containerId
    if ($LASTEXITCODE -ne 0) { throw 'Imagen no verificable' }
    $http = $probe | docker run --rm --pull never -i --network $network --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 $runner python -I -B -
    if ($LASTEXITCODE -ne 0) { throw 'No se verificó HTTP 200 en la raíz pública' }
    $http = $http | ConvertFrom-Json
} finally {
    if ($containerId -match '^[0-9a-f]{64}$') {
        docker rm -f -v $containerId | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $remaining = docker ps -a --filter "id=$containerId" --format '{{.ID}}'
            $removed = $LASTEXITCODE -eq 0 -and -not $remaining
        }
    }
    docker network rm $networkId | Out-Null
    $networkRemoved = $LASTEXITCODE -eq 0
}
if (-not ($removed -and $networkRemoved)) { throw 'Limpieza no verificada' }
$result = [ordered]@{ laboratory = 'OWASP Juice Shop'; synthetic = $false; timestamp_utc = [DateTime]::UtcNow.ToString('o'); image = $image; image_id = $imageId; internal_network = $true; published_ports = 0; http = $http; target_removed = $removed; network_removed = $networkRemoved; exploitability_validated = $false }
$stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 5) + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
} finally { $stream.Dispose() }
$result | ConvertTo-Json -Depth 5
