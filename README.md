[![Go Reference](https://pkg.go.dev/badge/aead.dev/minisign.svg)](https://pkg.go.dev/aead.dev/minisign)

# minisign
minisign is a dead simple tool to sign files and verify signatures.  
This is a Go implementation of the [original C implementation](https://github.com/jedisct1/minisign) by [Frank Denis](https://github.com/jedisct1).

## Library

The following example generates a minisign public/private key pair, signs a message and verifies the message signature.  
For more examples visit the Go package [documentation](https://pkg.go.dev/aead.dev/minisign).

```Go
package main

import (
	"crypto/rand"
	"log"

	"aead.dev/minisign"
)

func main() {
	const message = "Hello World!"

	public, private, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}

	signature := minisign.Sign(private, []byte(message))
	if !minisign.Verify(public, []byte(message), signature) {
		log.Fatalln("Signature verification failed")
	}
	log.Println(message)
}
```
