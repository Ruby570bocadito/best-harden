// mkmirror prepara un espejo de releases local para probar los instaladores
// y "adarve update" de punta a punta (scripts/e2e, job «Instaladores de punta
// a punta» del CI).
//
// Genera una clave de firma de prueba y compila Adarve para este sistema con
// esa clave en lugar de la real (go build -overlay: el fichero del
// repositorio no se toca). Deja en -out:
//
//	mirror/latest/download/version.txt          → v9.9.9
//	mirror/download/v9.9.8/…                     → release firmada
//	mirror/download/v9.9.9/…                     → release firmada (la última)
//	mirror/download/v9.9.7/…                     → checksums.txt manipulado tras firmar
//	mirror/download/v9.9.6/…                     → sin checksums.txt.sig
//	local/…                                      → v9.9.8 para --local / -Local
//	install.sh, install.ps1                      → con la clave pública de prueba
//
// La clave privada de prueba no se guarda: solo sirve para esta ejecución.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const module = "github.com/Ruby570bocadito/adarve"

func main() {
	out := flag.String("out", "", "carpeta de salida (se crea)")
	repo := flag.String("repo", ".", "raíz del repositorio")
	flag.Parse()
	if *out == "" {
		log.Fatal("falta -out")
	}
	root, err := filepath.Abs(*repo)
	check(err)
	dir, err := filepath.Abs(*out)
	check(err)
	check(os.MkdirAll(dir, 0o755))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	check(err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	// El binario confía en la clave de prueba.
	pubFile := filepath.Join(dir, "release-signing.pub")
	check(os.WriteFile(pubFile, pubPEM, 0o644))
	overlay := filepath.Join(dir, "overlay.json")
	ov, err := json.Marshal(map[string]map[string]string{"Replace": {
		filepath.Join(root, "internal", "selfupdate", "release-signing.pub"): pubFile,
	}})
	check(err)
	check(os.WriteFile(overlay, ov, 0o644))

	// Los instaladores, también.
	realPEM, err := os.ReadFile(filepath.Join(root, "internal", "selfupdate", "release-signing.pub"))
	check(err)
	sh, err := os.ReadFile(filepath.Join(root, "scripts", "install.sh"))
	check(err)
	sh = replaceOnce(sh, bytes.TrimSpace(realPEM), bytes.TrimSpace(pubPEM), "install.sh")
	check(os.WriteFile(filepath.Join(dir, "install.sh"), sh, 0o755)) // #nosec G703 -- herramienta de prueba: la carpeta la da -out
	ps, err := os.ReadFile(filepath.Join(root, "scripts", "install.ps1"))
	check(err)
	realX, realY := coords(realPEM)
	testX, testY := coords(pubPEM)
	ps = replaceOnce(ps, realX, testX, "install.ps1 (X)")
	ps = replaceOnce(ps, realY, testY, "install.ps1 (Y)")
	check(os.WriteFile(filepath.Join(dir, "install.ps1"), ps, 0o644)) // #nosec G703 -- herramienta de prueba: la carpeta la da -out

	asset := fmt.Sprintf("adarve_%s_%s", runtime.GOOS, runtime.GOARCH)
	exe := "adarve"
	if runtime.GOOS == "windows" {
		asset += ".zip"
		exe += ".exe"
	} else {
		asset += ".tar.gz"
	}

	mirror := filepath.Join(dir, "mirror")
	release := func(tag string, sign bool, tamper bool) []byte {
		bin := build(root, overlay, dir, strings.TrimPrefix(tag, "v"))
		archive := pack(bin, exe, strings.HasSuffix(asset, ".zip"))
		sum := sha256.Sum256(archive)
		sums := []byte(fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), asset))
		d := filepath.Join(mirror, "download", tag)
		check(os.MkdirAll(d, 0o755))
		check(os.WriteFile(filepath.Join(d, asset), archive, 0o644))
		if sign {
			h := sha256.Sum256(sums)
			sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
			check(err)
			check(os.WriteFile(filepath.Join(d, "checksums.txt.sig"), sig, 0o644))
		}
		if tamper {
			// Una línea más después de firmar: la firma ya no vale.
			sums = append(sums, []byte(strings.Repeat("0", 64)+"  otro.zip\n")...)
		}
		check(os.WriteFile(filepath.Join(d, "checksums.txt"), sums, 0o644))
		return archive
	}
	release("v9.9.8", true, false)
	release("v9.9.9", true, false)
	release("v9.9.7", true, true)
	release("v9.9.6", false, false)
	check(os.MkdirAll(filepath.Join(mirror, "latest", "download"), 0o755))
	check(os.WriteFile(filepath.Join(mirror, "latest", "download", "version.txt"), []byte("v9.9.9\n"), 0o644))

	local := filepath.Join(dir, "local")
	check(os.MkdirAll(local, 0o755))
	for _, f := range []string{asset, "checksums.txt", "checksums.txt.sig"} {
		b, err := os.ReadFile(filepath.Join(mirror, "download", "v9.9.8", f))
		check(err)
		check(os.WriteFile(filepath.Join(local, f), b, 0o644)) // #nosec G703 -- herramienta de prueba: la carpeta la da -out
	}
	fmt.Printf("espejo listo en %s (%s)\n", mirror, asset)
}

// build compila Adarve con la versión dada y la clave de prueba.
func build(root, overlay, dir, ver string) string {
	bin := filepath.Join(dir, "build", ver, "adarve")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-trimpath", "-overlay", overlay, "-o", bin,
		"-ldflags", "-s -w -X "+module+"/internal/version.Version="+ver+" -X "+module+"/internal/version.Repo=Ruby570bocadito/adarve",
		"./cmd/adarve")
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	check(cmd.Run())
	return bin
}

// pack empaqueta el binario como lo hace GoReleaser.
func pack(bin, name string, isZip bool) []byte {
	data, err := os.ReadFile(bin)
	check(err)
	var buf bytes.Buffer
	if isZip {
		zw := zip.NewWriter(&buf)
		w, err := zw.Create(name)
		check(err)
		_, err = w.Write(data)
		check(err)
		check(zw.Close())
		return buf.Bytes()
	}
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	check(tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}))
	_, err = tw.Write(data)
	check(err)
	check(tw.Close())
	check(gz.Close())
	return buf.Bytes()
}

// coords devuelve X e Y de una clave pública P-256 en base64, como las
// lleva install.ps1.
func coords(pemBytes []byte) ([]byte, []byte) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		log.Fatal("clave pública no válida")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	check(err)
	pt, err := k.(*ecdsa.PublicKey).Bytes()
	check(err)
	return []byte(base64.StdEncoding.EncodeToString(pt[1:33])), []byte(base64.StdEncoding.EncodeToString(pt[33:]))
}

func replaceOnce(s, old, new []byte, what string) []byte {
	if bytes.Count(s, old) != 1 {
		log.Fatalf("%s: la clave pública real no aparece exactamente una vez", what)
	}
	return bytes.Replace(s, old, new, 1)
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
