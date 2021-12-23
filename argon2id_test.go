package argon2id_test

import (
	"bytes"
	"testing"

	"github.com/dhenkes/argon2id"
)

func TestEncodeToBase64String(t *testing.T) {
	t.Run("NilBytes", func(t *testing.T) {
		if s := argon2id.EncodeToBase64String(nil); s != "" {
			t.Fatal("Exptected pre-defined string.")
		}
	})

	t.Run("ValidString", func(t *testing.T) {
		if s := argon2id.EncodeToBase64String([]byte("validstring")); s != "dmFsaWRzdHJpbmc" {
			t.Fatal("Exptected pre-defined string.")
		}
	})

	t.Run("InvalidString", func(t *testing.T) {
		if s := argon2id.EncodeToBase64String([]byte("validstring")); s == "amFsaWRzdHJpbmc" {
			t.Fatal("Did not exptect pre-defined string.")
		}
	})
}

func TestDecodeBase64String(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		if b, err := argon2id.DecodeBase64String(""); err != nil {
			t.Fatal(err)
		} else if bytes.Equal(b, []byte("")) != true {
			t.Fatal("Exptected pre-defined bytes.")
		}
	})

	t.Run("ValidString", func(t *testing.T) {
		if b, err := argon2id.DecodeBase64String("dmFsaWRzdHJpbmc"); err != nil {
			t.Fatal(err)
		} else if bytes.Equal(b, []byte("validstring")) != true {
			t.Fatal("Exptected pre-defined bytes.")
		}
	})

	t.Run("InvalidString", func(t *testing.T) {
		if b, err := argon2id.DecodeBase64String("dmFsaWRzdHJpbmc"); err != nil {
			t.Fatal(err)
		} else if bytes.Equal(b, []byte("invalidstring")) == true {
			t.Fatal("Did not expect pre-defined bytes.")
		}
	})

	t.Run("InvalidBase64", func(t *testing.T) {
		if b, err := argon2id.DecodeBase64String("amFsaWRzdHJpbmc"); err != nil {
			t.Fatal(err)
		} else if bytes.Equal(b, []byte("validstring")) == true {
			t.Fatal("Did not expect pre-defined bytes.")
		}
	})
}

func TestHashPassword(t *testing.T) {
	// password:salt
	verify := "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$OWwmnKFemKE2ILjM60j1so1oRXDFJYqvOiYlZTByvuU"

	t.Run("EmptyPassword", func(t *testing.T) {
		if _, err := argon2id.HashPassword("", "salt", argon2id.DefaultOptions); err == nil {
			t.Fatal("Expected error.")
		}
	})

	t.Run("EmptySalt", func(t *testing.T) {
		if _, err := argon2id.HashPassword("password", "", argon2id.DefaultOptions); err == nil {
			t.Fatal("Expected error.")
		}
	})

	t.Run("ValidHash", func(t *testing.T) {
		if h, err := argon2id.HashPassword("password", "salt", argon2id.DefaultOptions); err != nil {
			t.Fatal(err)
		} else if h != verify {
			t.Fatal("Expected pre-defined hash.")
		}
	})

	t.Run("InvalidHash", func(t *testing.T) {
		if h, err := argon2id.HashPassword("password", "salt1", argon2id.DefaultOptions); err != nil {
			t.Fatal(err)
		} else if h == verify {
			t.Fatal("Did not expext pre-defined hash.")
		}
	})
}

func TestVerifyPassword(t *testing.T) {
	// password:salt
	key := "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$OWwmnKFemKE2ILjM60j1so1oRXDFJYqvOiYlZTByvuU"

	t.Run("ValidVerification", func(t *testing.T) {
		t.Run("EmptyPassword", func(t *testing.T) {
			if err := argon2id.VerifyPassword("", key); err == nil {
				t.Fatal("Expected error.")
			}
		})

		t.Run("EmptyKey", func(t *testing.T) {
			if err := argon2id.VerifyPassword("password", ""); err == nil {
				t.Fatal("Expected error.")
			}
		})

		t.Run("WrongLength", func(t *testing.T) {
			if err := argon2id.VerifyPassword("password", "$argon2id$v=19"); err == nil {
				t.Fatal("Expected error.")
			}
		})

		t.Run("VersionMismatch", func(t *testing.T) {
			if err := argon2id.VerifyPassword("password", "$argon2id$v=1$m=65536,t=1,p=4$=$="); err == nil {
				t.Fatal("Expected error.")
			}
		})

		t.Run("ValidKey", func(t *testing.T) {
			if err := argon2id.VerifyPassword("password", key); err != nil {
				t.Fatal("Did not expext error.")
			}
		})

		t.Run("InvalidKey", func(t *testing.T) {
			if err := argon2id.VerifyPassword("password", key+"1"); err == nil {
				t.Fatal("Expected error.")
			}
		})

		t.Run("InvalidPassword", func(t *testing.T) {
			if err := argon2id.VerifyPassword("password1", key); err == nil {
				t.Fatal("Expected error.")
			}
		})
	})
}
