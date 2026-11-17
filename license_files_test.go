package main

import (
	"bytes"
	"os"
	"testing"
)

// sdk/LICENSE は root の LICENSE の写しである。sdk は別 module なので、gocredits が
// root の CREDITS を作るときに sdk/ の中にライセンスのファイルを探す(replace ./sdk の
// 参照先を読む)。写しが古くなると、CREDITS とアーカイブに古い条文が載る。
func TestSDKLicenseIsACopyOfTheRootLicense(t *testing.T) {
	t.Parallel()

	root, err := os.ReadFile("LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := os.ReadFile("sdk/LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, sdk) {
		t.Error("sdk/LICENSE differs from LICENSE; copy LICENSE over it")
	}
}
