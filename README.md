[![Go Reference](https://pkg.go.dev/badge/aead.dev/minisign.svg)](https://pkg.go.dev/aead.dev/minisign)

# minisign
minisign is a dead simple tool to sign files and verify signatures.  
This is a Go implementation of the [original C implementation](https://github.com/jedisct1/minisign) by [Frank Denis](https://github.com/jedisct1).

## Library

```Go
import "aead.dev/minisign" 
```

The following example generates a minisign public/private key pair, signs a message and verifies the message signature.

```Go
package main

import (
	"crypto/rand"
	"log"

	"aead.dev/minisign"
)

func main() {
	var message = []byte("Hello World!")

	public, private, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}

	signature := minisign.Sign(private, message)
	
	if !minisign.Verify(public, message, signature) {
		log.Fatalln("signature verification failed")
	}
	log.Println(string(message))
}
```
For more examples visit the package [documentation](https://pkg.go.dev/aead.dev/minisign).
