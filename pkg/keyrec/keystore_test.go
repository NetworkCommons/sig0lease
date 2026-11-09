package keyrec

import "testing"

// A directory given explicitly wins, CLIENT_KEYSTORE_DIR is the fallback, and with neither the
// error says both ways to give one.
func TestKeystoreDir(t *testing.T) {
	t.Setenv(KeystoreEnv, "/env/keys")
	if dir, err := KeystoreDir("/given", "pass -keystore=<dir>"); err != nil || dir != "/given" {
		t.Errorf("given: %q, %v; want /given", dir, err)
	}
	if dir, err := KeystoreDir("", "pass -keystore=<dir>"); err != nil || dir != "/env/keys" {
		t.Errorf("from the environment: %q, %v; want /env/keys", dir, err)
	}
	t.Setenv(KeystoreEnv, "")
	_, err := KeystoreDir("", "pass -keystore=<dir>")
	if want := "keystore directory is required: pass -keystore=<dir> or set CLIENT_KEYSTORE_DIR"; err == nil || err.Error() != want {
		t.Errorf("neither: %v; want %q", err, want)
	}
}
