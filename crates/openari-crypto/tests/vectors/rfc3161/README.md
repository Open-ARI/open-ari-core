# RFC 3161 test tokens

Synthetic data generated with OpenSSL 3.0.13 on 2026-10-31. Not Apple data.
The keys are not included. Licensed with the project (Apache-2.0).

| File | Contents |
| --- | --- |
| `ca.der` | Self-signed ECDSA P-256 root, CN "OpenARI Test Timestamp Root" |
| `tsa.der` | TSA certificate, serial 0x0A11, critical EKU id-kp-timeStamping |
| `other.der` | Second TSA certificate with a different key, serial 0x0B22 |
| `tsa-noeku.der` | TSA key and serial without the EKU extension |
| `message.txt` | Timestamped message |
| `token.der` | Token with nonce and embedded certificate (serial 0x02) |
| `token-nocert.der` | Token without nonce or certificate (serial 0x03) |

Both tokens pass `openssl ts -verify -data message.txt -token_in -CAfile ca.crt
-untrusted tsa.crt`. Expected field values in `tests/rfc3161.rs` come from
`openssl ts -reply -in TOKEN -token_in -text`.

Generation outline:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 36500 \
  -subj "/CN=OpenARI Test Timestamp Root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -out ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out tsa.key
openssl req -new -key tsa.key -subj "/CN=OpenARI Test TSA" -out tsa.csr
# tsa.ext: basicConstraints=critical,CA:FALSE; keyUsage=critical,digitalSignature;
#          extendedKeyUsage=critical,timeStamping; subjectKeyIdentifier=hash
openssl x509 -req -in tsa.csr -CA ca.crt -CAkey ca.key -set_serial 0x0a11 \
  -days 36500 -sha256 -extfile tsa.ext -out tsa.crt
# ts.cnf: signer_digest = sha256, ess_cert_id_alg = sha256, accuracy = secs:1,
#         default_policy = 1.3.6.1.4.1.99999.1
openssl ts -query -data message.txt -sha256 -cert -out q.tsq
openssl ts -reply -config ts.cnf -queryfile q.tsq -signer tsa.crt -inkey tsa.key -token_out -out token.der
openssl ts -query -data message.txt -sha256 -no_nonce -out q2.tsq
openssl ts -reply -config ts.cnf -queryfile q2.tsq -signer tsa.crt -inkey tsa.key -token_out -out token-nocert.der
```
