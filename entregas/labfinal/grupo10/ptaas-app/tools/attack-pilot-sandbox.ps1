$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$image = 'ptaas-attack-pilot-test:local'

# Construcción con acceso al índice de paquetes, sin contexto del repositorio.
@'
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN python -m pip install --no-cache-dir "pydantic>=2.12,<3" "pytest>=8,<10" "PyYAML>=6,<7"
'@ | docker build --tag $image -
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# El contenedor de pruebas no tiene red, credenciales ni socket de Docker.
$dockerArgs = @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '64',
    '--memory', '256m', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '--workdir', '/app')
foreach ($dir in @('runtime', 'prompts', 'harness', 'tests')) {
    $dockerArgs += @('--mount', "type=bind,source=$root/$dir,target=/app/$dir,readonly")
}
$dockerArgs += @($image, 'python', '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_attack_pilot.py', 'tests/test_roe.py', 'tests/test_defensive_report.py')
docker @dockerArgs
exit $LASTEXITCODE
