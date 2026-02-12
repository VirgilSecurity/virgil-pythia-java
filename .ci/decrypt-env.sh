#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_FILE="${1:-$ROOT_DIR/env.json.enc}"
OUTPUT_FILE="${2:-$ROOT_DIR/env.json}"

PASSPHRASE="${ENV_JSON_PASSPHRASE:-}"
KEY_HEX="${ENV_JSON_ENC_KEY:-}"
IV_HEX="${ENV_JSON_ENC_IV:-}"

if [[ ! -f "${INPUT_FILE}" ]]; then
  echo "Input file not found: ${INPUT_FILE}"
  exit 1
fi

# Preferred: passphrase-based encryption (portable across CI providers).
if [[ -n "${PASSPHRASE}" ]]; then
  # Base64 + PBKDF2 format (matches .ci/encrypt-env.sh)
  openssl enc -d -aes-256-cbc -pbkdf2 -a \
    -in "${INPUT_FILE}" \
    -out "${OUTPUT_FILE}" \
    -pass "pass:${PASSPHRASE}"
  echo "Decrypted (passphrase) ${INPUT_FILE} -> ${OUTPUT_FILE}"
  exit 0
fi

# Legacy: Travis-style key/iv encryption (binary).
if [[ -n "${KEY_HEX}" && -n "${IV_HEX}" ]]; then
  openssl aes-256-cbc \
    -K "${KEY_HEX}" \
    -iv "${IV_HEX}" \
    -in "${INPUT_FILE}" \
    -out "${OUTPUT_FILE}" \
    -d
  echo "Decrypted (key/iv) ${INPUT_FILE} -> ${OUTPUT_FILE}"
  exit 0
fi

cat <<'EOF'
No decryption secret provided.

Set one of:
- ENV_JSON_PASSPHRASE (preferred; for base64+pbkdf2 encrypted env.json.enc)
- ENV_JSON_ENC_KEY and ENV_JSON_ENC_IV (legacy; hex-encoded key/iv for binary env.json.enc)
EOF
exit 1

