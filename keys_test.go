package sshkeys

import "testing"
import "math/big"
import "crypto/rsa"

var samplePublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCoVOS1NOnZqTC/twA4K/fU9tYSUuoD9E9YJLge9s8IGuQSkEa0FA+jQ6RUCdnjmjkg1QPLGvxZ+hXMt+JPwQOiqXqpp5/yHtKyXWQ/zThSDKx5b99V4wztVcmQm15Xn94yzspOxaf2huAndgOL3toUZikgAxnHOhDrwuMwS36IoQ== testing public key"

var samplePrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCoVOS1NOnZqTC/twA4K/fU9tYSUuoD9E9YJLge9s8IGuQSkEa0
FA+jQ6RUCdnjmjkg1QPLGvxZ+hXMt+JPwQOiqXqpp5/yHtKyXWQ/zThSDKx5b99V
4wztVcmQm15Xn94yzspOxaf2huAndgOL3toUZikgAxnHOhDrwuMwS36IoQIDAQAB
AoGADGFSANHHcS60WyVGatsw+wS8cdSPSYMqYr0wnXZhe6Meqw7ZZF0lWUicSWIA
GHE7SmLgSIvPi36NI+VSS7NSZQGjFoCGdFHy0YlsVBHaluNMDQ4UTI9nlXzMt0/a
6mMuyat6H3eIuZII8s0bSBhHwcW8omF4+26CirWn7dve5pECQQDcVcP7jaxPimB9
McogZt3chE6SZAakwN5G9xqHuNMQ0egAPqkrP0kuWkySV7AOCHIYfiySnL7yXYFj
89rRcJP7AkEAw5Q2bElAeiL0z4bvSr0E+kBeKhqBZZekmdvNkzWmpsegTZm5fDsn
kcAFe3YLo8mqFaqFESIOd9JeQDPEmQgXEwJAY4/lxU/ZYv/WZfwPp+CTtEec8Y19
awkz58FVHasoxNr1CNdHviEUwntPSnmRNmYemG67WWy24/HYu/+/CxDh7QJBALIJ
mt1KdYp5hdfg4rZriTtyGwZC6KYdvDZfdC1c+p76PIBHvyVLCENSxOrV09S+wLlG
aCnnkbob47aYKZCRX8cCQQCbOy8Lv0QprqB7fss66jgicwOi4tDHhn1Y9O4r31oU
qT1uc/F5ltXLrq7JhtnpdQgVgiN63iZrZYg9L5+JHQTW
-----END RSA PRIVATE KEY-----`

func TestKeysMatch(t *testing.T) {
	var n *big.Int
	if k, err := DecodePrivateKeyBytes([]byte(samplePrivateKey)); err != nil {
		t.Error("Failed to decode private key:", err)
	} else {
		if k, ok := k.(*rsa.PrivateKey); !ok {
			t.Error("Didn't return an object of type *rsa.PrivateKey:", k)
		} else {
			if err := k.Validate(); err != nil {
				t.Error("Key validation failed:", err)
			}
			n = k.N
		}
	}

	if k, err := DecodePublicKeyBytes([]byte(samplePublicKey)); err != nil {
		t.Error("Failed to decode public key:", err)
	} else {
		if k, ok := k.(*rsa.PublicKey); !ok {
			t.Error("Didn't return an object of type *rsa.PublicKey:", k)
		} else {
			if k.N.Cmp(n) != 0 {
				t.Error("Public and private values of N did not match")
			}
		}
	}
}
