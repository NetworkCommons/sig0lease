SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_KEYSTORE_DIR="./keystore/client"

source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/dns.sh"

delete_rr "$@"