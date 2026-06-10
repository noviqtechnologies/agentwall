#!/usr/bin/env bash

# Basic syntax and validation test for install.sh
set -e

SCRIPT_PATH="$(dirname "$0")/../install.sh"

echo "[*] Running install_script_test.sh"

# 1. Check if script exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "[!] Error: install.sh not found at $SCRIPT_PATH"
    exit 1
fi

# 2. Check syntax using bash -n
echo "[*] Checking syntax of install.sh..."
bash -n "$SCRIPT_PATH"
echo "[✓] Syntax check passed."

# We will skip executing the actual installation to avoid polluting the host
# or hitting GitHub API limits during CI.
# If we wanted to test full execution we could mock curl and unzip by prepending
# mock functions.

echo "
mock_curl() {
    echo 'Mock curl called with args: \$@'
    # return mock JSON for the API call
    if [[ \"\$*\" == *api.github.com* ]]; then
        echo '{\"tag_name\": \"v99.99.99\"}'
    else
        # touch the output zip file
        eval touch \"\${@: -1}\"
    fi
}

mock_unzip() {
    echo 'Mock unzip called with args: \$@'
    # create dummy binary file
    mkdir -p \"\$5/release/bin\"
    touch \"\$5/release/bin/agentwall\"
    touch \"\$5/release/bin/agentwall.exe\"
}
" > /tmp/mock_funcs.sh

echo "[*] Running mocked execution test..."
# Create a test environment with mocked commands
bash -c "
source /tmp/mock_funcs.sh
alias curl=mock_curl
alias unzip=mock_unzip
export HOME=/tmp/agentwall_test_home
mkdir -p \$HOME
# We need to expand aliases in the non-interactive shell
shopt -s expand_aliases
source $SCRIPT_PATH
"

if [ -f "/tmp/agentwall_test_home/.local/bin/agentwall" ]; then
    echo "[✓] Mocked execution test passed."
else
    echo "[!] Mocked execution test failed to produce the binary in \$HOME/.local/bin/agentwall"
    exit 1
fi

echo "[✓] All tests passed."
