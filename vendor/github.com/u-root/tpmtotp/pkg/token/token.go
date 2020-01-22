package token

import (
	"image"
	"os"
	"runtime"

	"github.com/eliukblau/pixterm/pkg/ansimage"
	"github.com/lucasb-eyer/go-colorful"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh/terminal"
)

func isTerminal() bool {
	return terminal.IsTerminal(int(os.Stdout.Fd()))
}

func getTerminalSize() (width, height int, err error) {
	if isTerminal() {
		return terminal.GetSize(int(os.Stdout.Fd()))
	}
	// fallback when piping to a file!
	return 80, 24, nil // VT100 terminal size
}

// PrintTotpInAnsii prints QRcode in the terminal
func PrintTotpInAnsii(qrCode image.Image) error {
	ansimage.ClearTerminal()

	bgColour, err := colorful.Hex("#000000")
	if err != nil {
		return err
	}

	x, y, err := getTerminalSize()
	if err != nil {
		return err
	}

	pix, err := ansimage.NewScaledFromImage(qrCode, 4*x, 2*y, bgColour, ansimage.ScaleModeFit, ansimage.NoDithering)
	if err != nil {
		return err
	}
	pix.SetMaxProcs(runtime.NumCPU())
	pix.Draw()

	return nil
}

// CreateQRSecretTOTP generates a totp secret encoded in a QR code
func CreateQRSecretTOTP() (string, image.Image, error) {
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TPMTotp",
		AccountName: "tpmtotp@u-root.com",
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		return "", nil, err
	}

	image, err := secret.Image(60, 60)
	if err != nil {
		return "", nil, err
	}

	return secret.String(), image, nil
}

// CreateQRSecretHOTP generates a hotp secret encoded in a QR code
func CreateQRSecretHOTP() (string, image.Image, error) {
	secret, err := hotp.Generate(hotp.GenerateOpts{
		Issuer:      "TPMTotp",
		AccountName: "tpmtotp@u-root.com",
		Algorithm:   otp.AlgorithmSHA256,
	})
	if err != nil {
		return "", nil, err
	}
	image, err := secret.Image(60, 60)
	if err != nil {
		return "", nil, err
	}

	return secret.String(), image, nil
}
