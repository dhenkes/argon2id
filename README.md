# argon2id

This package provides a wrapper around Go's argon2 using the argon2id variant.
It provides multiple helper functions to make a secure implementation easier.

## Usage

```go
package main

import (
  "log"

  "github.com/dhenkes/argon2id"
)

func main() {
  // HashPassword returns the argon2 key (hash) of a given password.
  hash, err := argon2id.HashPassword("securepassword", "randomsalt", argon2id.DefaultOptions)
  if err != nil {
    log.Fatal(err)
  }

  // VerifyPassword takes a given argon2 hash and a plaintext password and
  // compares both. It will return an error if an issue occurs or the given
  // password does not match the hash.
  err = argon2id.VerifyPassword("securepassword", hash)
  if err == argon2id.ErrHashNotEqualPassword {
    log.Printf("Hash does not match password.")
    return
  }

  if err != nil {
    log.Fatal(err)
  }

  log.Printf("Hash matches password.")
}
```