SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_KEYSTORE_DIR="./keystore/client"

source "$SCRIPT_DIR/utils.sh"

delete_rr "$@"