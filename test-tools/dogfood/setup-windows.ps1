$ErrorActionPreference = "Stop"

$DogfoodDir = "C:\agentwall-dogfood"
Write-Host "Creating dogfood project in $DogfoodDir"
if (-Not (Test-Path "$DogfoodDir\src")) {
    New-Item -ItemType Directory -Force -Path "$DogfoodDir\src" | Out-Null
}
Set-Content -Path "$DogfoodDir\.gitignore" -Value "node_modules"
Set-Content -Path "$DogfoodDir\src\main.py" -Value "import os`r`ndef hello():`r`n    return 'world'"

Write-Host "Creating honeypots"
$Profile = $env:USERPROFILE

# Fake AWS creds
if (-Not (Test-Path "$Profile\.aws")) {
    New-Item -ItemType Directory -Force -Path "$Profile\.aws" | Out-Null
}
Set-Content -Path "$Profile\.aws\credentials" -Value "[default]`r`naws_access_key_id = AKIAIOSFODNN7EXAMPLE`r`naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Fake SSH key
if (-Not (Test-Path "$Profile\.ssh")) {
    New-Item -ItemType Directory -Force -Path "$Profile\.ssh" | Out-Null
}
Set-Content -Path "$Profile\.ssh\id_rsa.agentwall-test" -Value "-----BEGIN OPENSSH PRIVATE KEY-----`r`nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW`r`nQyNTUxOQAAACB8Xr4iJW3fF+hZGWZtT4ZyEVv5K1Ee+5SGJtFkN+Kj1QAAABh0ZXN0a2V5`r`ndGVzdGtleXRlc3RrZXk=`r`n-----END OPENSSH PRIVATE KEY-----"

# Fake .env
Set-Content -Path "$Profile\.env.agentwall-test" -Value "STRIPE_KEY=sk_test_placeholder_key_abc123`r`nOPENAI_KEY=openai_key_placeholder"

Write-Host "Creating daily log file"
if (-Not (Test-Path "$DogfoodDir\DOGFOOD_LOG.md")) {
    New-Item -ItemType File -Force -Path "$DogfoodDir\DOGFOOD_LOG.md" | Out-Null
}

Write-Host "Windows setup complete."
