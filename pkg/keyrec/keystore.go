// File: pkg/keyrec/keystore.go
// Where a client's keystore directory comes from.

package keyrec

import (
	"fmt"
	"os"
)

// KeystoreEnv names the environment variable every client of this project falls back to for
// its keystore directory.
const KeystoreEnv = "CLIENT_KEYSTORE_DIR"

// KeystoreDir applies the keystore-location convention shared by sig0lease-client,
// sig0lease-srp-client and sig0lease-agent: a directory given explicitly (a flag, a
// template's keystore:) wins, CLIENT_KEYSTORE_DIR is the fallback, and having neither is an
// error, which says how to give one: how, such as "pass -keystore=<dir>", or CLIENT_KEYSTORE_DIR.
func KeystoreDir(given, how string) (string, error) {
	if given != "" {
		return given, nil
	}
	if env := os.Getenv(KeystoreEnv); env != "" {
		return env, nil
	}
	return "", fmt.Errorf("keystore directory is required: %s or set %s", how, KeystoreEnv)
}
