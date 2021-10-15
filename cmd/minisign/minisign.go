// Copyright (c) 2021 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"aead.dev/minisign"
	"golang.org/x/term"
)

const usage = `Usage:
    minisign -G [-p <pubKey>] [-s <secKey>]
    minisign -S [-x <signature>] [-s <secKey>] [-c <comment>] [-t <comment>] -m <file>...
    minisign -V [-H] [-x <signature>] [-p <pubKey> | -P <pubKey>] [-o] [-q | -Q ] -m <file>
    minisign -R [-s <secKey>] [-p <pubKey>]
 
Options:
    -G               Generate a new public/secret key pair.       
    -S               Sign files with a secret key.
    -V               Verify files with a public key.
    -m <file>        The file to sign or verify.
    -o               Combined with -V, output the file after verification.
    -H               Combined with -V, require a signature over a pre-hashed file.
    -p <pubKey>      Public key file (default: ./minisign.pub)
    -P <pubKey>      Public key as base64 string
    -s <secKey>      Secret key file (default: $HOME/.minisign/minisign.key)
    -x <signature>   Signature file (default: <file>.minisig)
    -c <comment>     Add a one-line untrusted comment.
    -t <comment>     Add a one-line trusted comment.
    -q               Quiet mode. Suppress output.
    -Q               Pretty quiet mode. Combined with -V, only print the trusted comment.
    -R               Re-create a public key file from a secret key.
    -f               Combined with -G or -R, overwrite any existing public/secret key pair.
    -v               Print version information.
`

var version string = "v0.0.0-dev"

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var (
		keyGenFlag           bool
		signFlag             bool
		verifyFlag           bool
		filesFlag            = multiFlag{}
		outputFlag           bool
		hashFlag             bool
		pubKeyFileFlag       string
		pubKeyFlag           string
		secKeyFileFlag       string
		signatureFlag        string
		untrustedCommentFlag string
		trustedCommentFlag   string
		quietFlag            bool
		prettyQuietFlag      bool
		recreateFlag         bool
		forceFlag            bool
		versionFlag          bool
	)
	flag.BoolVar(&keyGenFlag, "G", false, "Generate a new public/secret key pair")
	flag.BoolVar(&signFlag, "S", false, "Sign files with a secret key")
	flag.BoolVar(&verifyFlag, "V", false, "Verify files with a public key")
	flag.Var(&filesFlag, "m", "One or multiple files to sign or verfiy")
	flag.BoolVar(&outputFlag, "o", false, "Combined with -V, output the file after verification")
	flag.BoolVar(&hashFlag, "H", false, "Combined with -S, pre-hash in order to sign large files")
	flag.StringVar(&pubKeyFileFlag, "p", "minisign.pub", "Public key file (default: minisign.pub")
	flag.StringVar(&pubKeyFlag, "P", "", "Public key as base64 string")
	flag.StringVar(&secKeyFileFlag, "s", filepath.Join(os.Getenv("HOME"), ".minisign/minisign.key"), "Secret key file (default: $HOME/.minisign/minisign.key")
	flag.StringVar(&signatureFlag, "x", "", "Signature file (default: <file>.minisig)")
	flag.StringVar(&untrustedCommentFlag, "c", "", "Add a one-line untrusted comment")
	flag.StringVar(&trustedCommentFlag, "t", "", "Add a one-line trusted comment")
	flag.BoolVar(&quietFlag, "q", false, "Quiet mode. Suppress output")
	flag.BoolVar(&prettyQuietFlag, "Q", false, "Pretty quiet mode. Combined with -V, only print the trusted comment")
	flag.BoolVar(&recreateFlag, "R", false, "Re-create a public key file from a secret key")
	flag.BoolVar(&forceFlag, "f", false, "Combined with -G, overwrite any existing public/secret key pair")
	flag.BoolVar(&versionFlag, "v", false, "Print version information")
	os.Args = append(os.Args[:1:1], expandFlags(os.Args[1:])...) // Expand flags to parse combined flags '-Vm' or '-Gf' properly
	flag.Parse()

	if versionFlag {
		fmt.Printf("minisign %s on %s-%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	switch {
	case keyGenFlag:
		generateKeyPair(secKeyFileFlag, pubKeyFileFlag, forceFlag)
	case signFlag:
		signFiles(secKeyFileFlag, signatureFlag, untrustedCommentFlag, trustedCommentFlag, filesFlag...)
	case verifyFlag:
		verifyFile(signatureFlag, pubKeyFileFlag, pubKeyFlag, outputFlag, quietFlag, prettyQuietFlag, hashFlag, filesFlag...)
	case recreateFlag:
		recreateKeyPair(secKeyFileFlag, pubKeyFileFlag, forceFlag)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func generateKeyPair(secKeyFile, pubKeyFile string, force bool) {
	if !force {
		_, err := os.Stat(secKeyFile)
		if err == nil {
			log.Fatalf("Error: %s already exists. Use -f if you really want to overwrite the existing key pair", secKeyFile)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Error: %v", err)
		}

		_, err = os.Stat(pubKeyFile)
		if err == nil {
			log.Fatalf("Error: %s already exists. Use -f if you really want to overwrite the existing key pair", pubKeyFile)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Error: %v", err)
		}
	}

	if dir := filepath.Dir(secKeyFile); dir != "" && dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error: %v", err)
		}
	}
	if dir := filepath.Dir(pubKeyFile); dir != "" && dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Error: %v", err)
		}
	}

	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("Please enter a password to protect the secret key.\n\n")
		password = readPassword(os.Stdin, "Enter Password: ")
		passwordAgain := readPassword(os.Stdin, "Enter Password (one more time): ")
		if password != passwordAgain {
			log.Fatal("Error: passwords don't match")
		}
	} else {
		password = readPassword(os.Stdin, "Enter Password: ")
	}
	publicKey, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Print("Deriving a key from the password in order to encrypt the secret key... ")
	encryptedPrivateKey, err := minisign.EncryptKey(password, privateKey)
	if err != nil {
		fmt.Println()
		log.Fatalf("Error: %v", err)
	}
	fmt.Print("done\n\n")

	var fileFlags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if !force {
		fileFlags |= os.O_EXCL // fail if the file already exists
	}
	skFile, err := os.OpenFile(secKeyFile, fileFlags, 0600)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer skFile.Close()
	if _, err = skFile.Write(encryptedPrivateKey); err != nil {
		log.Fatalf("Error: %v", err)
	}

	pkFile, err := os.OpenFile(pubKeyFile, fileFlags, 0644)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	defer pkFile.Close()

	rawPublicKey, _ := publicKey.MarshalText()
	if _, err = pkFile.Write(rawPublicKey); err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Printf("The secret key was saved as %s - Keep it secret!\n", secKeyFile)
	fmt.Printf("The public key was saved as %s - That one can be public.\n", pubKeyFile)
	fmt.Println()
	fmt.Println("Files signed using this key pair can be verified with the following command:")
	fmt.Println()
	fmt.Printf("minisign -Vm <file> -P %s\n", publicKey)
}

func signFiles(secKeyFile, sigFile, untrustedComment, trustedComment string, files ...string) {
	if len(files) == 0 {
		log.Fatal("Error: no files to sign. Use -m to specify one or more file paths")
	}
	if len(files) > 1 && sigFile != "" {
		log.Fatal("Error: -x cannot be used when more than one file should be signed")
	}
	for _, name := range files {
		stat, err := os.Stat(name)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if stat.IsDir() {
			log.Fatalf("Error: %s is a directory", name)
		}
	}

	encryptedPrivateKey, err := os.ReadFile(secKeyFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	password := readPassword(os.Stdin, "Enter password: ")

	fmt.Print("Deriving a key from the password in order to decrypt the secret key... ")
	privateKey, err := minisign.DecryptKey(password, encryptedPrivateKey)
	if err != nil {
		fmt.Println()
		log.Fatalf("Error: invalid password: %v", err)
	}
	fmt.Print("done\n\n")

	if sigFile != "" {
		if dir := filepath.Dir(sigFile); dir != "" && dir != "." && dir != "/" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.Fatalf("Error: %v", err)
			}
		}
	}

	for _, name := range files {
		var signature []byte
		file, err := os.Open(name)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		var tComment, uComment = trustedComment, untrustedComment
		if uComment == "" {
			uComment = "signature from minisign secret key"
		}
		if tComment == "" {
			tComment = fmt.Sprintf("timestamp:%d\tfilename:%s", time.Now().Unix(), filepath.Base(name))
		}
		var reader = minisign.NewReader(file)
		if _, err = io.Copy(io.Discard, reader); err != nil {
			file.Close()
			log.Fatalf("Error: %v", err)
		}
		signature = reader.SignWithComments(privateKey, tComment, uComment)
		file.Close()

		var signatureFile = name + ".minisig"
		if sigFile != "" {
			signatureFile = sigFile
		}
		if err = os.WriteFile(signatureFile, signature, 0644); err != nil {
			log.Fatalf("Error: %v", err)
		}
	}
}
func verifyFile(sigFile, pubFile, pubKeyString string, printOutput, quiet, prettyQuiet, requireHash bool, files ...string) {
	if len(files) == 0 {
		log.Fatalf("Error: no files to verify. Use -m to specify a file path")
	}
	if len(files) > 1 {
		log.Fatalf("Error: too many files to verify. Only one file can be specified")
	}
	if sigFile == "" {
		sigFile = files[0] + ".minisig"
	}

	var (
		publicKey minisign.PublicKey
		err       error
	)
	if pubKeyString != "" {
		if err = publicKey.UnmarshalText([]byte(pubKeyString)); err != nil {
			log.Fatalf("Error: invalid public key: %v", err)
		}
	} else {
		publicKey, err = minisign.PublicKeyFromFile(pubFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	}

	signature, err := minisign.SignatureFromFile(sigFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if signature.KeyID != publicKey.ID() {
		log.Fatalf("Error: key IDs do not match. Try a different public key.\nID (public key): %X\nID (signature) : %X", publicKey.ID(), signature.KeyID)
	}

	rawSignature, _ := signature.MarshalText()
	if requireHash && signature.Algorithm != minisign.HashEdDSA {
		log.Fatal("Legacy (non-prehashed) signature found")
	}
	if signature.Algorithm == minisign.HashEdDSA || requireHash {
		file, err := os.Open(files[0])
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		reader := minisign.NewReader(file)
		if _, err = io.Copy(io.Discard, reader); err != nil {
			file.Close()
			log.Fatalf("Error: %v", err)
		}

		if !reader.Verify(publicKey, rawSignature) {
			file.Close()
			log.Fatal("Error: signature verification failed")
		}
		if !quiet {
			if !prettyQuiet {
				fmt.Println("Signature and comment signature verified")
			}
			fmt.Println("Trusted comment:", signature.TrustedComment)
		}
		if printOutput {
			if _, err = file.Seek(0, io.SeekStart); err != nil {
				file.Close()
				log.Fatalf("Error: %v", err)
			}
			if _, err = io.Copy(os.Stdout, bufio.NewReader(file)); err != nil {
				file.Close()
				log.Fatalf("Error: %v", err)
			}
		}
		file.Close()
	} else {
		message, err := os.ReadFile(files[0])
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
		if !minisign.Verify(publicKey, message, rawSignature) {
			log.Fatal("Error: signature verification failed")
		}
		if !quiet {
			if !prettyQuiet {
				fmt.Println("Signature and comment signature verified")
			}
			fmt.Println("Trusted comment:", signature.TrustedComment)
		}
		if printOutput {
			os.Stdout.Write(message)
		}
	}
}

func recreateKeyPair(secKeyFile, pubKeyFile string, force bool) {
	if !force {
		if _, err := os.Stat(pubKeyFile); err == nil {
			log.Fatalf("Error: %s already exists. Use -f if you really want to overwrite the existing key pair", pubKeyFile)
		}
	}
	if _, err := os.Stat(secKeyFile); err != nil {
		log.Fatalf("Error: %v", err)
	}

	password := readPassword(os.Stdin, "Enter password: ")
	fmt.Print("Deriving a key from the password in order to encrypt the secret key... ")
	privateKey, err := minisign.PrivateKeyFromFile(password, secKeyFile)
	if err != nil {
		fmt.Println()
		log.Fatalf("Error: invalid password: %v", err)
	}
	fmt.Println("done")

	publicKey := privateKey.Public().(minisign.PublicKey)
	rawPublicKey, _ := publicKey.MarshalText()
	if err = os.WriteFile(pubKeyFile, rawPublicKey, 0644); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func readPassword(file *os.File, message string) string {
	if !term.IsTerminal(int(file.Fd())) { // If file is not a terminal read the password directly from it
		p, err := bufio.NewReader(file).ReadString('\n')
		if err != nil {
			log.Fatalf("Error: failed to read password: %v", err)
		}
		return strings.TrimSuffix(p, "\n") // ReadString contains the trailing '\n'
	}

	fmt.Fprint(file, message)
	p, err := term.ReadPassword(int(file.Fd()))
	fmt.Fprintln(file)

	if err != nil {
		log.Fatalf("Error: failed to read password: %v", err)
	}
	return string(p)
}

func expandFlags(args []string) []string {
	expArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			expArgs = append(expArgs, arg)
			continue
		}

		if len(arg) > 2 {
			expArgs = append(expArgs, arg[:2])
			for _, a := range arg[2:] {
				expArgs = append(expArgs, "-"+string(a))
			}
		} else {
			expArgs = append(expArgs, arg)
		}
	}
	return expArgs
}

type multiFlag []string

var _ flag.Value = (*multiFlag)(nil) // compiler check

func (f *multiFlag) String() string { return fmt.Sprint(*f) }

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
