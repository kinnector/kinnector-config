#!/bin/bash
set -e

# Compile JSON policy template into cryptographically signed rules.db
# Usage: ./compile.sh [input_policy.json] [output_rules.db] [private_key_file]

INPUT_JSON=${1:-"../kinnector-protect-community/policies/"}
OUTPUT_DB=${2:-"rules.db"}
PRIVATE_KEY=$3

echo "[*] Compiling policies: $INPUT_JSON -> $OUTPUT_DB"
if [ -n "$PRIVATE_KEY" ]; then
    cargo run --release --bin compile_policy "$INPUT_JSON" "$OUTPUT_DB" "$PRIVATE_KEY"
else
    cargo run --release --bin compile_policy "$INPUT_JSON" "$OUTPUT_DB"
fi
