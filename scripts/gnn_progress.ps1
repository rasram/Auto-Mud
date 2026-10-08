param([switch]$Watch, [switch]$Json)
$arguments = @('-d','automud','--cd','/home/jayan/Auto-Mud','--exec','/home/jayan/Auto-Mud/.venv/bin/python','scripts/gnn_progress.py')
if ($Watch) { $arguments += '--watch' }
if ($Json) { $arguments += '--json' }
& wsl.exe @arguments
exit $LASTEXITCODE
