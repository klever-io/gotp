package main

import (
	"fmt"

	"github.com/klever-io/gotp"
)

func main() {
	fmt.Println("Random secret:", gotp.RandomSecret(16))
	defaultTOTPUsage()
	defaultHOTPUsage()
}

func defaultTOTPUsage() {
	otp := gotp.NewDefaultTOTP("4S62BZNFXXSZLCRO")

	otpNow, err := otp.Now()
	if err != nil {
		fmt.Println("unable to generate current one-time password")
		return
	}

	fmt.Println("current one-time password is:", otpNow)

	otpAt, err := otp.At(0)
	if err != nil {
		fmt.Println("unable to get one-time of timestamp 0")
		return
	}

	fmt.Println("one-time password of timestamp 0 is:", otpAt)
	fmt.Println(otp.ProvisioningUri("demoAccountName", "issuerName"))

	fmt.Println(otp.Verify("179394", 1524485781))
}

func defaultHOTPUsage() {
	otp := gotp.NewDefaultHOTP("4S62BZNFXXSZLCRO")

	otpAt, err := otp.At(0)
	if err != nil {
		fmt.Println("unable to get one-time of timestamp 0")
		return
	}

	fmt.Println("one-time password of counter 0 is:", otpAt)
	fmt.Println(otp.ProvisioningUri("demoAccountName", "issuerName", 1))

	fmt.Println(otp.Verify("944181", 0))
}
