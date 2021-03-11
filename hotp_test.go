package gotp

import (
	"testing"
)

var hotp = NewDefaultHOTP("4S62BZNFXXSZLCRO")

func TestHOTP_At(t *testing.T) {
	hotpAt, err := hotp.At(12345)
	if err != nil {
		t.Error(err.Error())
	}

	otp := hotpAt
	if "194001" != otp {
		t.Error("HOTP generate otp error")
	}
}

func TestHOTP_Verify(t *testing.T) {
	ok, err := hotp.Verify("194001", 12345)
	if err != nil {
		t.Error(err.Error())
	}

	if !ok {
		t.Error("verify faild")
	}
}
