#!/bin/bash
#
# End to end tests of the archway 'config' commands against a local node
#

echo "››› CONFIG"

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_NAME="test-config"
TEMP_DIR="$(mktemp -d -t "$PROJECT_NAME.XXXXXX")"

source "${SCRIPT_DIR}/../../.env"
source "${SCRIPT_DIR}/utils.sh"

function cleanup_test_suite() {
  echo "Cleaning up the created files"
  cd "$SCRIPT_DIR"
  rm -rf "$TEMP_DIR"
}

trap cleanup_test_suite EXIT
trap cleanup ERR

CHAIN_ID=constantine-3

echo "Initializing project in $TEMP_DIR"
git init "$TEMP_DIR"
cd "$TEMP_DIR"

echo "***** config init *****"
output="$(archway config init --chain $CHAIN_ID --json)"
validate "$output" ".[\"chain-id\"] == \"$CHAIN_ID\""
fileExists "${TEMP_DIR}/.archway/config.json" "Config file created" "Config file not found"

printf "\n***** config show ***** \n"
output="$(archway config show --json)"
validate "$output" ".[\"chain-id\"] == \"$CHAIN_ID\""

printf "\n***** config deployments ***** \n"
output="$(archway config deployments --json)"
validate "$output" ".deployments == []"

printf "\n***** config chains import ***** \n"
output="$(archway config chains import "$(scriptRelativePath ../../scripts/local-1.json)" --json --force)"
validate "$output" '.["chain-id"] == "local-1"'

printf "\n***** config chains use ***** \n"
output="$(archway config chains use local-1 --json)"
validate "$output" '.["chain-id"] == "local-1"'

echo
ok SUCCESS
