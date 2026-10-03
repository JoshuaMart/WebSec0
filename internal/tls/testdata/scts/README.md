# Independent SCT certificate fixture

`google-leaf.pem` is the unchanged `googleLeaf` certificate from
[Go 1.27.1, crypto/x509/verify_test.go](https://github.com/golang/go/blob/go1.27.1/src/crypto/x509/verify_test.go).
The Go project's BSD license is retained in `LICENSE-Go`.

This public certificate for `www.google.com` contains two embedded v1 SCTs.
It expired in March 2023. The test only parses the certificate and extracts
the SCTs: it does not validate trust, dates or signatures, contact the host,
or depend on the Go installation's test data.

Certificate SHA-256 fingerprint:
`6263c84dc05ffa91ebe2b459377d22c3063d99bb765fe06c2275e6dc4e2c8334`.

Expected log IDs, in certificate order, independently decoded with OpenSSL:

1. `7a328c54d8b72db620ea38e0521ee98416703213854d3bd22bc13a57a352eb52`
2. `e83ed0da3ef5063532e75728bc896bc903d3cbd1116beceb69e1777d6d06bd6e`

To inspect the fixture from the repository root:

```sh
openssl x509 -in internal/tls/testdata/scts/google-leaf.pem -noout -text
openssl x509 -in internal/tls/testdata/scts/google-leaf.pem -noout -sha256 -fingerprint
go test ./internal/tls -run '^TestCertificateSCTsReference$' -v
```

OpenSSL is only used for manual inspection, not by the test. Keep this fixture
independent of `fixtureSCT` and `fixtureSCTExtension`; do not regenerate it
with the parser's synthetic test helpers.
