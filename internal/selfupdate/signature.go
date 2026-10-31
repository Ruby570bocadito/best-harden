package selfupdate

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
)

// releaseKeys son las claves públicas que firman checksums.txt en cada
// release (ECDSA P-256 sobre SHA-256, firma DER en checksums.txt.sig). La
// suma SHA-256 sola viaja por el mismo canal que el binario; la firma prueba
// que la release la publicó quien tiene la clave privada, aunque el espejo o
// la cuenta de descarga estén comprometidos.
//
// La misma clave está en scripts/install.sh y scripts/install.ps1 (un test
// lo comprueba). Para rotarla se añade la nueva aquí y se firma con ella;
// la antigua se retira cuando ya no quedan versiones que solo la conozcan.
//
//go:embed release-signing.pub
var releaseKeysPEM []byte

// ErrUnsigned indica que la release no publica checksums.txt.sig.
var ErrUnsigned = errors.New("la release no está firmada (falta checksums.txt.sig)")

func releaseKeys() ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	rest := releaseKeysPEM
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := k.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("clave de firma de tipo %T no admitida", k)
		}
		keys = append(keys, ec)
	}
	if len(keys) == 0 {
		return nil, errors.New("no hay claves de firma de releases")
	}
	return keys, nil
}

// VerifyChecksums comprueba que sig es una firma válida de sums con alguna
// de las claves de las releases.
func VerifyChecksums(sums, sig []byte) error {
	keys, err := releaseKeys()
	if err != nil {
		return err
	}
	return verifyWith(keys, sums, sig)
}

func verifyWith(keys []*ecdsa.PublicKey, sums, sig []byte) error {
	h := sha256.Sum256(sums)
	for _, k := range keys {
		if ecdsa.VerifyASN1(k, h[:], sig) {
			return nil
		}
	}
	return errors.New("la firma de checksums.txt no es válida: la release no la publicó Adarve o se ha manipulado")
}
