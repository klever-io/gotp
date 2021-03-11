package gotp

import (
	"testing"
)

var totp = NewDefaultTOTP("4S62BZNFXXSZLCRO")

func TestTOTP_At(t *testing.T) {
	totpNow, err := totp.Now()
	if err != nil {
		t.Error(err.Error())
	}

	totpAt, err := totp.At(currentTimestamp())
	if err != nil {
		t.Error(err.Error())
	}

	if totpNow != totpAt {
		t.Error("TOTP generate otp error!")
	}
}

func TestTOTP_NowWithExpiration(t *testing.T) {
	otp, exp, err := totp.NowWithExpiration()
	if err != nil {
		t.Error(err.Error())
	}

	cts := currentTimestamp()

	totpNow, err := totp.Now()
	if err != nil {
		t.Error(err.Error())
	}

	if otp != totpNow {
		t.Error("TOTP generate otp error!")
	}

	totpAt0, err := totp.At(cts + 30)
	if err != nil {
		t.Error(err.Error())
	}

	totpAt1, err := totp.At(int(exp))
	if err != nil {
		t.Error(err.Error())
	}

	if totpAt0 != totpAt1 {
		t.Error("TOTP expiration otp error!")
	}
}

func TestTOTP_Verify(t *testing.T) {
	ok, err := totp.Verify("179394", 1524485781)
	if err != nil {
		t.Error(err.Error())
	}

	if !ok {
		t.Error("verify faild")
	}
}

func TestTOTP_ProvisioningUri(t *testing.T) {
	expect := "otpauth://totp/github:xlzd?secret=4S62BZNFXXSZLCRO&issuer=github"

	uri, err := totp.ProvisioningUri("xlzd", "github")
	if err != nil {
		t.Error(err.Error())
	}

	if expect != uri {
		t.Error("ProvisioningUri error")
	}
}
