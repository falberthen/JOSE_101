# Sample tokens and payloads

`payloads/` holds the editable JSON claims the console app reads before every sign/encrypt
operation — edit those files to try your own claims, no rebuild needed. The files below are
pre-generated output tokens, made with the demo keys in [`/keys`](../keys), so you can
inspect them without running the app. **Do not treat these as secrets** — the
signing/encryption keys are public in this repo (see [`keys/README.md`](../keys/README.md)).

| File | Type | Header (`alg` / `enc`) | Paste into jwt.io? |
|---|---|---|---|
| `jws-hmac.jwt` | JWS | HS256 | Yes — decodes header + payload; signature check needs the HMAC secret |
| `jws-rsa.jwt` | JWS | RS256 | Yes — paste `keys/rsa-public.pem` as the verification key to check the signature |
| `jws-ecdsa.jwt` | JWS | ES256 | Yes — paste `keys/ec-public.pem` as the verification key to check the signature |
| `jwe-direct.jwe` | JWE | dir / A256GCM | Header only — jwt.io cannot decrypt JWE payloads |
| `jwe-rsa-oaep.jwe` | JWE | RSA-OAEP / A256GCM | Header only — jwt.io cannot decrypt JWE payloads |
| `nested-jws-then-jwe.jwe` | Nested (JWS inside JWE) | dir / A256GCM, `cty: JWT` | Header only — decrypt first (menu `2` → `6`, `signWith: rsa`, `encryptWith: dir`) to see the inner JWS |

The three JWS samples and the nested one encode `{"sub":"alice","role":"admin"}`
(see `payloads/claims-basic.json`). Both JWE samples encode `{"sub":"alice","ssn":"redacted"}`
(see `payloads/claims-sensitive.json`). Edit either file and the app signs or encrypts your
own claims, which of course produces tokens that no longer match the ones above.

To decrypt the JWE/nested samples or re-verify anything, run the console app
(`dotnet run --project src/JOSE_101.ConsoleApp`), pick "Verify / Decrypt", and paste a
token from this folder — or pick "Inspect" to see any token's header without running any
crypto.
