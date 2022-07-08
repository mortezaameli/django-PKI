# PKI

## API example

- Get valid values for some fields

certificate category list:
```
curl -X GET http://localhost/pki/valid-fields/cert-category/
```

private key info(Algorithms, Key size):
```
curl -X GET http://localhost/pki/valid-fields/key/
```
---
- Generate selfsign CA certificate
```
curl -H "Content-Type: application/json" \
  -d '{"name": "root-ca", "key_type": "RSA", "key_size": 2048, "validity_days": 365, "subject_info": {"id_type": "Domain Name", "subject": "rootCA", "organization": "ca_org", "organization_unit": ["ou1", "ou2"], "locality": "internal", "state": "Tehran", "country": "IR", "email": "ca@test.com"}}' \
  -X POST http://localhost/pki/cert/local/selfsign/generate/
```
---
- Specify issuer CA

Only one CA can set as issuer CA
```
curl -X PUT http://localhost/pki/cert/local/issuer-ca/<str:name>/
```
---
- Create CSR
```
curl -H "Content-Type: application/json" \
  -d '{"name": "cert1", "key_type": "RSA", "key_size": 1024, "privkey_pass": "csr1pass", "subject_info": {"id_type": "Domain Name", "subject": "test_client", "organization": "home", "organization_unit": ["room"], "locality": "Tehran", "state": "asia", "country": "IR", "email": "test@home"}}' \
  -X POST http://localhost/pki/cert/local/csr/generate/
```
---
- Sign local CSR(create crypto cert)
```
curl -H "Content-Type: application/json"\
  -d '{"category": "Local-Cert" ,"name": "cert1", "validity_days": 120}' \
  -X POST http://localhost/pki/cert/csr/sign/
```
---
- Sign local CSR(create intermediate CA)
```
curl -H "Content-Type: application/json"\
  -d '{"category": "Local-Cert" ,"name": "cert1", "validity_days": 120, "can_sign": true}' \
  -X POST http://localhost/pki/cert/csr/sign/
```
---
- Revoke Certificate
```
curl -H "Content-Type: application/json"\
  -d '{"category": "Local-Cert" ,"name": "cert1"}' \
  -X POST http://localhost/pki/cert/local/cert/revoke/
```
---
- Import remote CSR
```
curl -H "Content-Type: multipart/form-data" \
  -F "csr_file=@/home/morteza72/Desktop/test_for_remote.csr" \
  -X PUT http://localhost/pki/import/cert/remote/csr/
```
---
- Import local certificate
```
curl -H "Content-Type: multipart/form-data" \
  -F "cert_file=@/home/morteza72/Desktop/test_client.crt" \
  -X PUT http://localhost/pki/import/cert/local/cert/
```
---
- Import certificate with privkey
```
curl -H "Content-Type: multipart/form-data" \
  -F "cert_file=@/home/morteza72/Desktop/test.cert" \
  -F "key_file=@/home/morteza72/Desktop/test.key" \
  -F "key_pass=''" \
  -F "cert_name=cert_and_key" \
  -X PUT http://localhost/pki/import/cert/local/cert-with-key/
```
---
- Import remote Certificate
```
curl -H "Content-Type: multipart/form-data" \
  -F "cert_file=@/home/morteza72/Desktop/test.cert" \
  -X PUT http://localhost/pki/import/cert/remote/cert/
```
---
- Import remote CA(Trusted CA)
```
curl -H "Content-Type: multipart/form-data" \
  -F "ca_file=@/home/morteza72/Desktop/root-ca.cer" \
  -X PUT http://localhost/pki/import/cert/remote/ca/
```
---
- Generate CRL
```
curl -H "Content-Type: application/json" \
  -X POST http://localhost/pki/crl/generate/
```
After generate , Add it to CRL(Trusted CRL)

---
- CRL list
```
curl -X GET http://localhost/pki/crls/
```
---
- CRL details
```
curl -X GET http://localhost/pki/crl/<str:name>/
```
---
- Delete CRL
```
curl -X DELETE http://localhost/pki/crl/<str:name>/
```
---
- Download CRL
```
curl -X GET http://localhost/pki/download/crl/<str:name>/
```
---
- Import CRL(Trusted CRL)
```
curl -H "Content-Type: multipart/form-data" \
  -F "crl_file=@/home/morteza72/Desktop/test.crl" \
  -X PUT http://localhost/pki/import/crl/
```
---
- Import P12
```
curl -H "Content-Type: multipart/form-data" \
  -F "p12_file=@/home/morteza72/Desktop/test_for_remote.p12" \
  -F "p12_pass=123456789" \
  -F "cert_name=test-p12" \
  -X PUT http://localhost/pki/import/cert/local/p12/
```
---
- Delete certificate
```
curl -X DELETE http://localhost/pki/cert/cert/<str:category>/<str:name>/
```
---
- Certificates list
```
curl -X GET http://localhost/pki/certs/
```
---
- Certificate details
```
curl -X GET http://localhost/pki/cert/cert/<str:category>/<str:name>/
```
---
- CA certificate details
```
curl -X GET http://localhost/pki/cert/local/issuer-ca/
```
---
- Download CA certificate
```
curl -X GET http://localhost/pki/download/cert/local/issuer-ca/
```
---
- Download certificate
```
curl -X GET http://localhost/pki/download/cert/cert/<str:category>/<str:name>/
```
---
- Download P12
```
curl -H "Content-Type: application/json" \
  -d '{"name": "cert1", "p12pass": "123456789", "privkey_pass": "csr1pass"}' \
  -X GET http://localhost/pki/download/cert/local/p12/ \
  --output ~/cert1.p12
```
---
