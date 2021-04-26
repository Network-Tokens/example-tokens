# Example
Set of sample network tokens, along with code to generate them.

WARNING: This is Work In Progress. Field names are still a bit inconsistent.
The repo is currently used to store a few stable tokens and keys to use for development
and design discussions. 

## User-Centric Network Token

A user-centric, application agnostic, privacy preserving network token. 

### Token Header
The App ID for this service is 0x10001. This implies the token payload 
will be encrypted with the key mentioned below.

```app_id = 0x10001```

This is an origin bidirectional token (i.e., no reflection needed at the peer).

```reflect_type = 0```

### JWE Header
Token is encrypted with 128CBC-HS256, using direct symmetric encryption. We might
skip this header in the future to save space, as this information can be implied by the APP_ID.

```header = {'alg':'dir','enc':'A128CBC-HS256'}```

### Payload
Token is bound to IP bip. It expires on 01/01/2030, and comes with an nti (nonce) value for potential revocation.

```{'bip': '172.31.0.3', 'exp': 1893456000, 'nti': 151234143124}```

### Secret Key

The key used to encrypt and decrypt this token.

```{"k":"Qr_XwDGctna3SlR88rEJYt6Zm100SASYeJWSJihDnsA","kty":"oct"}```

### Token (JSON format)
The contents of the token payload in JSON format (fields are encoded as URL-safe base64

```{"ciphertext":"9r6WvC38pm7l0LbqFd4JZv3lhHzkWEKYlmabHCAVt-QYCu_g0LK8XZ0EQPCseaXOP3HkHUdD2oYgZ5UHBAeBIw","iv":"1K9eul7zPanY1uUzuymV-w","protected":"eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0","tag":"CKV7vctjDHfPQlKV9tnyQA"}```

### Token (compact format)
Compact representation of the token's payload (URL-safe base64)

```eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..1K9eul7zPanY1uUzuymV-w.9r6WvC38pm7l0LbqFd4JZv3lhHzkWEKYlmabHCAVt-QYCu_g0LK8XZ0EQPCseaXOP3HkHUdD2oYgZ5UHBAeBIw.CKV7vctjDHfPQlKV9tnyQA```

### Token (compact format) - HEX

Token in compact form, hex-encoded.

```65794a68624763694f694a6b615849694c434a6c626d4d694f694a424d54493451304a444c5568544d6a5532496e302e2e314b3965756c377a50616e593175557a75796d562d772e3972365776433338706d376c304c62714664344a5a76336c68487a6b57454b596c6d616248434156742d515943755f67304c4b38585a3045515043736561584f5033486b48556444326f59675a3555484241654249772e434b56377663746a44486650516c4b5639746e795141```

### Token (Compact with Token Header) - HEX

Token pre-pended with 4-byte token header (reflect type and app-id)

```0001000165794a68624763694f694a6b615849694c434a6c626d4d694f694a424d54493451304a444c5568544d6a5532496e302e2e314b3965756c377a50616e593175557a75796d562d772e3972365776433338706d376c304c62714664344a5a76336c68487a6b57454b596c6d616248434156742d515943755f67304c4b38585a3045515043736561584f5033486b48556444326f59675a3555484241654249772e434b56377663746a44486650516c4b5639746e795141```

