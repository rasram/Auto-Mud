param([string]$Run = 'local-v2-run')
if ($Run -notmatch '^[a-zA-Z0-9_-]+$') { throw 'Use a simple run directory name.' }
$project = Split-Path -Parent $PSScriptRoot
$source = "\\wsl.localhost\automud\home\jayan\Auto-Mud\data\gnn\$Run"
$destination = Join-Path $project "data\gnn\$Run"
if (-not (Test-Path -LiteralPath (Join-Path $source 'evaluation.json'))) { throw 'Evaluation is not complete yet.' }
New-Item -ItemType Directory -Path $destination -Force | Out-Null
foreach ($name in @('evaluation.json','evaluation.predictions.jsonl','development-coverage.json','pipeline-status.json','pipeline.log')) {
    Copy-Item -LiteralPath (Join-Path $source $name) -Destination $destination -Force
}
foreach ($name in @('model','prepared')) {
    $target = Join-Path $destination $name
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $source $name) -File | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $target -Force
    }
}
Write-Output "Reports, models and prepared graphs copied to $destination. Raw captures remain in WSL."
