# VEXA AgentWall Start Script
Write-Host "Starting VEXA AgentWall Bridge..." -ForegroundColor Cyan
Set-Location -Path ui
python bridge.py --vexa-bin ..\bin\agentwall.exe --policy ..\config\policy.yaml.example
