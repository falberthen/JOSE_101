# !️ Demo keys — NOT for production

Every key in this folder was generated only for this repo's demos:

```bash
openssl genrsa -out rsa-private.pem 2048
openssl rsa -in rsa-private.pem -pubout -out rsa-public.pem
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' > hmac-secret.txt
```

They are committed to source control on purpose so the sample project runs out of the box.
**Never reuse these files, or this generation method, for anything real.** Production keys
must be generated in a secure environment, stored in a secrets manager / HSM / KMS, and
never committed to git.

| File | Used by | Algorithm |
|---|---|---|
| `rsa-private.pem` / `rsa-public.pem` | JWS RS256, JWE RSA-OAEP | RSA 2048 |
| `ec-private.pem` / `ec-public.pem` | JWS ES256 | EC P-256 (prime256v1) |
| `hmac-secret.txt` | JWS HS256, JWE `dir` + A256GCM | 256-bit random secret (base64url) |
