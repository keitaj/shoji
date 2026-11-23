package main

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	der, err := readCert("../../testdata/" + name)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("mock fixtures not generated; run `make fixtures`")
		}
		t.Fatal(err)
	}
	return der
}

func TestMockCertificatePassesAllChecks(t *testing.T) {
	rep, err := inspect(load(t, "adult.pem"), load(t, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rep, "[FAIL]") {
		t.Fatalf("mock certificate should satisfy every check:\n%s", rep)
	}
	if !strings.Contains(rep, "classes DDDDDDDDD") {
		t.Fatal("date of birth should be reported by character class")
	}
}

// The report must never contain the holder's data.
func TestReportHidesContents(t *testing.T) {
	for _, name := range []string{"adult.pem", "decoy.pem"} {
		rep, err := inspect(load(t, name), load(t, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"19900115", "20150401", "19700101", "419900115", "検証", "東京都", "テスト町", "MOCK"} {
			if strings.Contains(rep, secret) {
				t.Fatalf("%s: report leaks %q", name, secret)
			}
		}
	}
}

func TestWrongIssuerIsReported(t *testing.T) {
	rep, err := inspect(load(t, "adult.pem"), load(t, "ca_other.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep, "[FAIL] certificate verifies under the issuer key") {
		t.Fatalf("expected a failed signature check:\n%s", rep)
	}
}
