package cipher_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/madstone-tech/cipher-core/pkg/cipher"
)

// Example shows the minimal round trip: open a local client, create a key,
// then encrypt and decrypt a file with it.
func Example() {
	dir, err := os.MkdirTemp("", "example-cipher-*")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	client, err := cipher.NewLocal(filepath.Join(dir, "example-cipher.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	created, err := client.CreateKey(ctx, "example", "a-strong-key-passphrase")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(created.Key.Alias)
	// Output: example
}
